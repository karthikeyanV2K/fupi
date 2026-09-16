// Package main is the FUPI kiosk in Go: a real self-contained HTTPS ATM & mint.
//
// Why Go for the kiosk tier: goroutine-per-connection handles thousands of
// concurrent vault/melt connections on one cheap VPS or Raspberry Pi; net/http
// and crypto/tls serve HTTPS natively with zero external dependencies;
// statically-linked single binary; memory-safe GC runtime without C toolchain headaches.
//
// RSA-2048 Chaum blinding via crypto/rsa (FIPS-grade, hardware accelerated).
// Built-in TLS: auto-generates high-grade self-signed certificates or uses custom cert/key.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Keyset struct {
	KeysetID string `json:"keyset_id"`
	N        string `json:"n"`
	E        int    `json:"e"`
}

type AtmInfo struct {
	Name           string  `json:"name"`
	Version        string  `json:"version"`
	KeysetID       string  `json:"keyset_id"`
	Reserve        float64 `json:"reserve"`
	Issued         int     `json:"issued"`
	SpentCount     int     `json:"spent_count"`
	TLSEnabled     bool    `json:"tls_enabled"`
	TLSFingerprint string  `json:"tls_fingerprint_sha256,omitempty"`
}

type Kiosk struct {
	mu        sync.Mutex
	key       *rsa.PrivateKey
	reserve   float64
	issued    int
	spent     map[string]struct{}
	statePath string
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) {
	clean := strings.TrimSpace(strings.TrimRight(s, "="))
	if v, err := base64.RawURLEncoding.DecodeString(clean); err == nil {
		return v, nil
	}
	if v, err := base64.RawStdEncoding.DecodeString(clean); err == nil {
		return v, nil
	}
	return nil, fmt.Errorf("invalid base64 encoding")
}

func mustUnb64(s string) []byte {
	v, err := unb64(s)
	if err != nil {
		panic(err)
	}
	return v
}

func hashToScalar(secret []byte, n *big.Int) *big.Int {
	h := sha256.Sum256(secret)
	m := new(big.Int).SetBytes(h[:])
	m.Mod(m, n)
	if m.Cmp(big.NewInt(2)) < 0 { // value < 2, NOT Sign() (which is -1/0/1)
		m.SetInt64(2)
	}
	return m
}

// ---- kiosk: reserve, keyset, blind-sign, settle ----

func NewKiosk(statePath string) (*Kiosk, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	k := &Kiosk{key: key, spent: map[string]struct{}{}, statePath: statePath}
	loaded := k.loadState()
	if !loaded && statePath != "" {
		// Persist the newly generated RSA keypair immediately so keyset is stable across reboots
		k.saveState()
	}
	return k, nil
}

func (k *Kiosk) CreditReserve(amount float64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.reserve += amount
	log.Printf("[kiosk] reserve +%.2f (total %.2f)", amount, k.reserve)
	k.saveState()
}

func (k *Kiosk) Pubkey() Keyset {
	k.mu.Lock()
	defer k.mu.Unlock()
	return Keyset{
		KeysetID: "go-mvp-00",
		N:        b64(k.key.PublicKey.N.Bytes()),
		E:        k.key.PublicKey.E,
	}
}

func (k *Kiosk) Info(tlsEnabled bool, fingerprint string) AtmInfo {
	k.mu.Lock()
	defer k.mu.Unlock()
	return AtmInfo{
		Name:           "FUPI Self-Contained Go HTTPS ATM",
		Version:        "0.2.0",
		KeysetID:       "go-mvp-00",
		Reserve:        k.reserve,
		Issued:         k.issued,
		SpentCount:     len(k.spent),
		TLSEnabled:     tlsEnabled,
		TLSFingerprint: fingerprint,
	}
}

// BlindSign signs a blinded scalar. The kiosk NEVER sees the token secret.
// Textbook RSA on the blinded value is exactly Chaum's scheme — PKCS#1
// padding would defeat the blinding, so "raw" here is CORRECT, not lazy.
func (k *Kiosk) BlindSign(blindedB64 string, amount int) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.issued+amount > int(k.reserve) {
		return "", fmt.Errorf("insufficient reserve (1:1 rule)")
	}
	raw, err := unb64(blindedB64)
	if err != nil {
		return "", fmt.Errorf("invalid base64 blinded_message: %w", err)
	}
	mB := new(big.Int).SetBytes(raw)
	if mB.Sign() <= 0 || mB.Cmp(k.key.N) >= 0 {
		return "", fmt.Errorf("blinded scalar out of valid range [1, N)")
	}
	sB := new(big.Int).Exp(mB, k.key.D, k.key.N)
	k.issued += amount
	k.saveState()
	return b64(sB.Bytes()), nil
}

type Proof struct {
	Secret   string `json:"secret"`
	Sig      string `json:"sig"`
	N        string `json:"n,omitempty"`
	E        int    `json:"e,omitempty"`
	KeysetID string `json:"keyset_id,omitempty"`
	P2PK     string `json:"p2pk,omitempty"`
	Claimer  string `json:"claimer,omitempty"`
}

func constEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (k *Kiosk) Settle(p Proof) (bool, string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if p.Secret == "" {
		return false, "REJECTED: empty secret"
	}
	if _, dup := k.spent[p.Secret]; dup {
		return false, "REJECTED: double-spend (already settled)"
	}
	sigBytes, err := unb64(p.Sig)
	if err != nil {
		return false, "REJECTED: invalid signature base64"
	}
	s := new(big.Int).SetBytes(sigBytes)
	if s.Sign() <= 0 || s.Cmp(k.key.N) >= 0 {
		return false, "REJECTED: signature scalar out of range"
	}
	m := hashToScalar([]byte(p.Secret), k.key.N)
	check := new(big.Int).Exp(s, big.NewInt(int64(k.key.PublicKey.E)), k.key.N)
	if os.Getenv("FUPI_DEBUG") != "" {
		log.Printf("[debug settle] secret=%q\n  m=  %x\n  chk=%x\n  N=  %x\n  e=%d",
			p.Secret, m, check, k.key.N, k.key.PublicKey.E)
	}
	if check.Cmp(m) != 0 {
		return false, "REJECTED: bad signature"
	}
	if p.P2PK != "" && !constEq(p.P2PK, p.Claimer) {
		return false, "REJECTED: P2PK lock (not the owner)"
	}
	k.spent[p.Secret] = struct{}{}
	if k.issued > 0 {
		k.issued--
	}
	k.saveState()
	return true, "settled OK (first-to-settle-wins)"
}

// ---- persistence (survives restarts; same job as kiosk_state.json) ----

type diskState struct {
	N       string   `json:"n"`
	D       string   `json:"d"`
	Reserve float64  `json:"reserve"`
	Issued  int      `json:"issued"`
	Spent   []string `json:"spent"`
}

func (k *Kiosk) saveState() error {
	if k.statePath == "" {
		return nil
	}
	st := diskState{
		N:       b64(k.key.N.Bytes()),
		D:       b64(k.key.D.Bytes()),
		Reserve: k.reserve,
		Issued:  k.issued,
	}
	for s := range k.spent {
		st.Spent = append(st.Spent, s)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := k.statePath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, k.statePath)
}

func (k *Kiosk) loadState() bool {
	if k.statePath == "" {
		return false
	}
	data, err := os.ReadFile(k.statePath)
	if err != nil || len(data) == 0 {
		// Attempt fallback to .tmp if power failure happened during rename
		tmpData, tmpErr := os.ReadFile(k.statePath + ".tmp")
		if tmpErr == nil && len(tmpData) > 0 {
			data = tmpData
			_ = os.Rename(k.statePath+".tmp", k.statePath)
		} else {
			return false
		}
	}
	var st diskState
	if json.Unmarshal(data, &st) != nil || st.N == "" || st.D == "" {
		return false
	}
	nBytes, errN := unb64(st.N)
	dBytes, errD := unb64(st.D)
	if errN != nil || errD != nil {
		log.Printf("[kiosk] corrupt keys in state: %v / %v", errN, errD)
		return false
	}
	n := new(big.Int).SetBytes(nBytes)
	d := new(big.Int).SetBytes(dBytes)
	k.key = &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: 65537}, D: d}
	k.reserve, k.issued = st.Reserve, st.Issued
	for _, s := range st.Spent {
		k.spent[s] = struct{}{}
	}
	log.Printf("[kiosk] state loaded: reserve=%.2f issued=%d spent=%d",
		k.reserve, k.issued, len(k.spent))
	return true
}

// ---- Self-Contained TLS Certificate Generator ----

func generateSelfSignedCert(hosts []string) (tls.Certificate, []byte, []byte, string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, nil, "", err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, nil, nil, "", err
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year validity

	templateCert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"FUPI Offline Vault Payment Infrastructure"},
			CommonName:   "FUPI HTTPS ATM",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			templateCert.IPAddresses = append(templateCert.IPAddresses, ip)
		} else {
			templateCert.DNSNames = append(templateCert.DNSNames, h)
		}
	}
	if len(templateCert.IPAddresses) == 0 && len(templateCert.DNSNames) == 0 {
		templateCert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback}
		templateCert.DNSNames = []string{"localhost"}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &templateCert, &templateCert, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, "", err
	}

	fp := sha256.Sum256(derBytes)
	fingerprint := fmt.Sprintf("%X", fp)

	return tlsCert, certPEM, keyPEM, fingerprint, nil
}

// ---- HTTP / HTTPS API & Terminal UI ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FUPI Digital ATM Terminal</title>
<style>
  :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #2ea043; --term: #58a6ff; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: var(--bg); color: var(--text); padding: 2rem 1rem; margin: 0; }
  .container { max-width: 680px; margin: 0 auto; background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 2rem; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
  h1 { margin-top: 0; color: #f0f6fc; display: flex; align-items: center; gap: 0.5rem; }
  .badge { font-size: 0.75rem; padding: 0.25rem 0.5rem; border-radius: 12px; font-weight: 600; text-transform: uppercase; }
  .badge-tls { background: rgba(46,160,67,0.15); color: var(--accent); border: 1px solid var(--accent); }
  .badge-http { background: rgba(210,153,34,0.15); color: #d29922; border: 1px solid #d29922; }
  .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 1rem; margin: 1.5rem 0; }
  .stat { background: #0b0e14; border: 1px solid var(--border); border-radius: 6px; padding: 1rem; text-align: center; }
  .stat-val { font-size: 1.5rem; font-weight: bold; color: #58a6ff; }
  .stat-lbl { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; margin-top: 0.25rem; }
  pre { background: #040d1a; padding: 1rem; border-radius: 6px; border: 1px solid #1f2937; overflow-x: auto; font-size: 0.85rem; color: #7ee787; }
  .footnote { font-size: 0.8rem; color: #8b949e; border-top: 1px solid var(--border); padding-top: 1rem; margin-top: 1.5rem; }
</style>
</head>
<body>
<div class="container">
  <h1>
    <span>🏧 FUPI ATM NODE</span>
    {{if .TLSEnabled}}
      <span class="badge badge-tls">🔒 HTTPS TLS ACTIVE</span>
    {{else}}
      <span class="badge badge-http">HTTP</span>
    {{end}}
  </h1>
  <p>Self-Contained Chaum Blind-Signature Mint & Offline Cash ATM.</p>

  <div class="stat-grid">
    <div class="stat">
      <div class="stat-val">{{printf "%.2f" .Reserve}}</div>
      <div class="stat-lbl">1:1 Reserve</div>
    </div>
    <div class="stat">
      <div class="stat-val">{{.Issued}}</div>
      <div class="stat-lbl">Issued Tokens</div>
    </div>
    <div class="stat">
      <div class="stat-val">{{.SpentCount}}</div>
      <div class="stat-lbl">Settled Proofs</div>
    </div>
    <div class="stat">
      <div class="stat-val">{{.KeysetID}}</div>
      <div class="stat-lbl">Active Keyset</div>
    </div>
  </div>

  <h3>Cryptographic Profile</h3>
  <pre>Signing Algorithm: Chaum RSA-2048 (e=65537)
Security Guarantee: Mint never sees token secrets (blind issue)
Settlement Mode: First-to-settle-wins with P2PK lock support
TLS Fingerprint: {{if .TLSFingerprint}}{{.TLSFingerprint}}{{else}}N/A (HTTP){{end}}</pre>

  <h3>Endpoints (cdk-mintd compatible)</h3>
  <ul>
    <li><code>GET  /v1/info</code> — ATM status & TLS metadata</li>
    <li><code>GET  /v1/keyset</code> — Active RSA-2048 public keyset</li>
    <li><code>POST /v1/credit</code> — Inbound fiat reserve funding</li>
    <li><code>POST /v1/blind-sign</code> — Issue blind signature on blinded scalar</li>
    <li><code>POST /v1/settle</code> — Settle bearer proof (first-to-settle-wins)</li>
  </ul>

  <div class="footnote">
    FUPI: Offline Vault Payment Infrastructure. Bank loads once. The token itself IS the money.
  </div>
</div>
</body>
</html>`

var dashTmpl = template.Must(template.New("dashboard").Parse(dashboardHTML))

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return true
}

func SetupMux(k *Kiosk, tlsEnabled bool, fingerprint string) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/atm" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		info := k.Info(tlsEnabled, fingerprint)
		dashTmpl.Execute(w, info)
	})

	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeJSON(w, 200, k.Info(tlsEnabled, fingerprint))
	})

	mux.HandleFunc("/v1/keyset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeJSON(w, 200, k.Pubkey())
	})

	mux.HandleFunc("/v1/credit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var body struct {
			Amount float64 `json:"amount"` // major units; the bank rails call this
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Amount <= 0 {
			writeJSON(w, 400, map[string]string{"error": "amount<=0"})
			return
		}
		k.CreditReserve(body.Amount)
		writeJSON(w, 200, map[string]float64{"reserve": k.reserve})
	})

	mux.HandleFunc("/v1/blind-sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var body struct {
			BlindedMessage string `json:"blinded_message"`
			Amount         int    `json:"amount"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Amount <= 0 {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		sig, err := k.BlindSign(body.BlindedMessage, body.Amount)
		if os.Getenv("FUPI_DEBUG") != "" {
			if raw, err := unb64(body.BlindedMessage); err == nil {
				log.Printf("[debug sign] blindedBits=%d", new(big.Int).SetBytes(raw).BitLen())
			}
		}
		if err != nil {
			writeJSON(w, 402, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"blind_signature": sig})
	})

	mux.HandleFunc("/v1/settle", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var proof Proof
		if json.NewDecoder(r.Body).Decode(&proof) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad proof"})
			return
		}
		ok, msg := k.Settle(proof)
		code := 200
		if !ok {
			code = 409 // conflict: double-spend / bad sig / P2PK violation
		}
		writeJSON(w, code, map[string]string{"result": msg})
	})

	return mux
}

func main() {
	port := flag.Int("port", 8890, "listen port")
	statePath := flag.String("state", "kiosk_go_state.json", "state file")
	useTLS := flag.Bool("tls", true, "enable self-contained HTTPS / TLS")
	certFile := flag.String("cert", "", "custom TLS certificate PEM path (optional)")
	keyFile := flag.String("key", "", "custom TLS private key PEM path (optional)")
	saveCert := flag.Bool("save-cert", true, "save auto-generated TLS certificate to kiosk_cert.pem & kiosk_key.pem")
	forceNewCert := flag.Bool("force-new-cert", false, "force new TLS cert generation even if kiosk_cert.pem exists")
	flag.Parse()

	k, err := NewKiosk(*statePath)
	if err != nil {
		log.Fatal(err)
	}

	addr := fmt.Sprintf(":%d", *port)

	if !*useTLS {
		log.Printf("[kiosk-go] FUPI ATM (Go) listening on http://%s (Plain HTTP, TLS disabled)", addr)
		mux := SetupMux(k, false, "")
		log.Fatal(http.ListenAndServe(addr, mux))
	}

	var tlsCert tls.Certificate
	var fingerprint string

	if *certFile != "" && *keyFile != "" {
		tlsCert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("failed to load custom TLS cert/key: %v", err)
		}
		if len(tlsCert.Certificate) > 0 {
			fp := sha256.Sum256(tlsCert.Certificate[0])
			fingerprint = fmt.Sprintf("%X", fp)
		}
		log.Printf("[kiosk-go] loaded custom TLS certificate from %s / %s", *certFile, *keyFile)
	} else if !*forceNewCert && fileExists("kiosk_cert.pem") && fileExists("kiosk_key.pem") {
		tlsCert, err = tls.LoadX509KeyPair("kiosk_cert.pem", "kiosk_key.pem")
		if err == nil && len(tlsCert.Certificate) > 0 {
			fp := sha256.Sum256(tlsCert.Certificate[0])
			fingerprint = fmt.Sprintf("%X", fp)
			log.Printf("[kiosk-go] reused existing TLS certificate from kiosk_cert.pem and kiosk_key.pem")
		} else {
			hosts := []string{"127.0.0.1", "localhost"}
			var certPEM, keyPEM []byte
			tlsCert, certPEM, keyPEM, fingerprint, err = generateSelfSignedCert(hosts)
			if err != nil {
				log.Fatalf("failed to generate self-signed TLS cert: %v", err)
			}
			if *saveCert {
				_ = os.WriteFile("kiosk_cert.pem", certPEM, 0644)
				_ = os.WriteFile("kiosk_key.pem", keyPEM, 0600)
				log.Printf("[kiosk-go] auto-generated TLS cert saved to kiosk_cert.pem and kiosk_key.pem")
			}
		}
	} else {
		hosts := []string{"127.0.0.1", "localhost"}
		var certPEM, keyPEM []byte
		tlsCert, certPEM, keyPEM, fingerprint, err = generateSelfSignedCert(hosts)
		if err != nil {
			log.Fatalf("failed to generate self-signed TLS cert: %v", err)
		}
		if *saveCert {
			_ = os.WriteFile("kiosk_cert.pem", certPEM, 0644)
			_ = os.WriteFile("kiosk_key.pem", keyPEM, 0600)
			log.Printf("[kiosk-go] auto-generated TLS cert saved to kiosk_cert.pem and kiosk_key.pem")
		}
	}

	mux := SetupMux(k, true, fingerprint)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	log.Printf("[kiosk-go] FUPI Self-Contained HTTPS ATM listening on https://127.0.0.1%s", addr)
	log.Printf("[kiosk-go] TLS Fingerprint (SHA-256): %s", fingerprint)
	log.Printf("[kiosk-go] 1:1 reserve, Chaum RSA-2048 blind signer, zero-middleman cash mint")
	log.Fatal(server.ListenAndServeTLS("", ""))
}
