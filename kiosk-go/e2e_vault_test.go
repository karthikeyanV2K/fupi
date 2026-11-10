// Package main — Go port of the retired e2e_https_rust_vault_test.py.
//
// End-to-end integration test: Go HTTPS kiosk <-> Rust vault over real TLS.
// The test spawns the real kiosk binary (with TLS + credit secret) and drives
// the real vault-rust binary through the full hardened flow with the SAME
// expected output strings as the Python original:
//
//	1. Kiosk boots with a credit secret; vault trusts ONLY the pinned TLS
//	   fingerprint
//	2. TLS: strict default and a wrong pin are both refused
//	3. Reserve funding is HMAC-authenticated; replayed ref / wrong secret refused
//	4. Device identity: no quota => no proofs; operator allocates; denominated
//	   top-up; 4b exact payment + change-making through /v1/swap
//	5. P2PK locks: claim signature required; wrong key / no key / relabelled /
//	   inflated refused
//	6. Offline replay rejection; outbox
//	7. Peer-to-peer offline receive
//	8. Forged tokens rejected (fake modulus, e=1)
//	9. 5-way concurrent settle race: exactly one winner
//	10. Merchant terminal: offline accept, replays refused, batch settle, a
//	    double-spending customer is caught on the receipt
//	11. Cash-out: settlement report, payout recorded, replay/overpay refused
//	12. Pilot daily check (go run ./pilot) — the Go port of pilot_check.py
//
// Skips cleanly when either binary has not been built yet.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	e2ePort        = "8896"
	e2eURL         = "https://127.0.0.1:" + e2ePort
	e2eCredit      = "e2e-credit-secret-not-for-production"
	e2eBadPinHex   = "0000000000000000000000000000000000000000000000000000000000000000"
	e2eVaultWhoami = 0
)

var (
	e2eDeviceKeyRe = regexp.MustCompile(`device_public_key=([0-9a-f]{64})`)
	e2ePubKeyRe    = regexp.MustCompile(`public_key=([0-9a-f]{64})`)
	e2eSecretKeyRe = regexp.MustCompile(`secret_key=([0-9a-f]{64})`)
)

type e2ePaths struct {
	root   string
	kiosk  string
	vault  string
	state  string
	pilot  string
	log    string
	flashs map[string]string
}

func e2eSetupPaths(t *testing.T) e2ePaths {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	kiosk := filepath.Join(root, "kiosk-go", "kiosk-go")
	vault := filepath.Join(root, "vault-rust", "target", "release", "fupi-vault")
	if _, err := os.Stat(vault); err != nil {
		vault = filepath.Join(root, "vault-rust", "target", "debug", "fupi-vault")
	}
	// Every run gets its own private workspace: leftovers (a .bak holding an
	// older kiosk's pinned keysets) cannot poison the next run.
	work := t.TempDir()
	p := e2ePaths{
		root:   root,
		kiosk:  kiosk,
		vault:  vault,
		state:  filepath.Join(work, "atm_state.json"),
		pilot:  filepath.Join("pilot"), // package dir for `go build`
		log:    filepath.Join(work, "pilot_log.jsonl"),
		flashs: map[string]string{
			"alice": filepath.Join(work, "flash_alice.json"),
			"bob":   filepath.Join(work, "flash_bob.json"),
			"shop":  filepath.Join(work, "flash_shop.json"),
		},
	}
	if _, err := os.Stat(kiosk); err != nil {
		t.Skipf("kiosk binary missing (%s): run `go build -o kiosk-go .` first", kiosk)
	}
	if _, err := os.Stat(vault); err != nil {
		t.Skipf("vault binary missing (%s): run `cargo build --release` in vault-rust first", vault)
	}
	return p
}

// e2eCleanup removes every state/flash file the test could have created.
func (p e2ePaths) cleanup() {
	bases := []string{p.state, p.log}
	for _, v := range p.flashs {
		bases = append(bases, v)
	}
	for _, base := range bases {
		for _, ext := range []string{"", ".tmp", ".bak"} {
			_ = os.Remove(base + ext)
		}
	}
}

// e2eJSON is a localhost-only reader (the vault itself pins the TLS fingerprint).
func e2eJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
	resp, err := client.Get(e2eURL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	if json.NewDecoder(resp.Body).Decode(&doc) != nil {
		t.Fatalf("GET %s: not JSON", path)
	}
	return doc
}

type e2eResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// e2eVault runs the vault binary exactly like the Python did: subcommand args,
// then --atm / --flash / TLS flags. env adds/overrides variables; FUPI_CREDIT_
// SECRET is always absent unless added.
func (p e2ePaths) e2eVault(who string, opt e2eOpt, args ...string) e2eResult {
	t := opt.t
	t.Helper()
	full := append(append([]string{}, args...), "--atm", e2eURL, "--flash", p.flashs[who])
	switch opt.tls {
	case "pin":
		full = append(full, "--pin-tls", opt.pin)
	case "badpin":
		full = append(full, "--pin-tls", e2eBadPinHex)
	case "insecure":
		full = append(full, "--insecure")
	case "strict":
		// no TLS flag at all: default must refuse a self-signed cert
	}
	cmd := exec.Command(p.vault, full...)
	env := e2eBaseEnv()
	for k, v := range opt.env {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	exit := 0
	if ee, ok := err.(*exec.ExitError); ok {
		exit = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("vault run (%v): %v", full, err)
	}
	return e2eResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exit}
}

func e2eBaseEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "FUPI_CREDIT_SECRET=") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

type e2eOpt struct {
	t   *testing.T
	tls string
	pin string
	env map[string]string // extra env, e.g. the operator secret
}

// e2eStep mirrors the Python step banners in verbose logs.
func e2eStep(t *testing.T, n any, title string) {
	t.Logf("[Step %v] %s", n, title)
}

// tokenValue sums the face values a token's keyset ids name.
func tokenValue(t *testing.T, tok string) int {
	t.Helper()
	clean := strings.TrimRight(tok, "=")
	decoded, err := base64.RawURLEncoding.DecodeString(clean)
	if err != nil {
		t.Fatalf("token is not base64url: %v", err)
	}
	var proofs []struct {
		KeysetID string `json:"keyset_id"`
	}
	if json.Unmarshal(decoded, &proofs) != nil {
		t.Fatalf("token is not a proof list")
	}
	total := 0
	for _, p := range proofs {
		if p.KeysetID == "go-mvp-00" || p.KeysetID == "" {
			total++
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(p.KeysetID, "go-mvp-d"))
		if err != nil {
			t.Fatalf("unknown keyset id %q", p.KeysetID)
		}
		total += n
	}
	return total
}

func lastLine(res e2eResult) string {
	lines := strings.Split(strings.TrimSpace(res.Stdout), "\n")
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}

func wantSub(t *testing.T, what string, s, want string) {
	t.Helper()
	if strings.Contains(s, want) {
		return
	}
	t.Errorf("%s: output missing %q\n--- stdout ---\n%s\n--- stderr ---\n%s", what, want, s, "")
}

func wantSubErr(t *testing.T, what string, res e2eResult, want string) {
	t.Helper()
	if strings.Contains(res.Stdout+res.Stderr, want) {
		return
	}
	t.Errorf("%s: output missing %q\n--- stdout ---\n%s\n--- stderr ---\n%s", what, want, res.Stdout, res.Stderr)
}

func e2eStartKiosk(t *testing.T, p e2ePaths) (pin string, stop func()) {
	t.Helper()
	cmd := exec.Command(p.kiosk, "-port", e2ePort, "-tls=true", "-state", p.state, "-save-cert=false")
	cmd.Dir = filepath.Join(p.root, "kiosk-go")
	cmd.Env = append(e2eBaseEnv(), "FUPI_CREDIT_SECRET="+e2eCredit)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start kiosk: %v", err)
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			t.Fatalf("kiosk exited early:\n%s", out.String())
		default:
		}
		if resp, err := client.Get(e2eURL + "/v1/info"); err == nil {
			var info map[string]any
			json.NewDecoder(resp.Body).Decode(&info)
			resp.Body.Close()
			if fp, ok := info["tls_fingerprint_sha256"].(string); ok && fp != "" {
				return fp, func() {
					cmd.Process.Kill()
					select {
					case <-done:
					case <-time.After(3 * time.Second):
					}
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	cmd.Process.Kill()
	t.Fatalf("kiosk did not come up on %s", e2eURL)
	return "", func() {}
}

func TestE2EHttpsRustVaultHardened(t *testing.T) {
	p := e2eSetupPaths(t)
	p.cleanup()
	defer p.cleanup()

	good := map[string]string{"FUPI_CREDIT_SECRET": e2eCredit}

	pin, stopKiosk := e2eStartKiosk(t, p)
	defer stopKiosk()
	t.Logf("kiosk TLS fingerprint: %s...", pin[:16])

	// Step 1 banner belongs above; fingerprint read means the kiosk is up.
	e2eStep(t, 2, "TLS trust: strict default and a wrong pin must both be REFUSED")
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "strict"}, "info"); r.ExitCode == 0 {
		t.Errorf("strict TLS accepted a self-signed certificate")
	}
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "badpin"}, "info"); r.ExitCode == 0 {
		t.Errorf("a wrong pin was accepted")
	}
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "info"); r.ExitCode != 0 {
		t.Fatalf("pinned TLS failed: %s%s", r.Stdout, r.Stderr)
	} else {
		wantSub(t, "info", r.Stdout, "TLS Active: true")
	}

	e2eStep(t, 3, "Reserve funding is authenticated and idempotent")
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "bank", "100", "--ref", "UTR-1"); r.ExitCode == 0 {
		t.Errorf("credit without FUPI_CREDIT_SECRET succeeded")
	}
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin,
		env: map[string]string{"FUPI_CREDIT_SECRET": "wrong"}}, "bank", "100", "--ref", "UTR-1"); r.ExitCode == 0 {
		t.Errorf("credit with the wrong secret was accepted")
	}
	good100 := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin, env: good}, "bank", "100", "--ref", "UTR-1")
	if good100.ExitCode != 0 {
		t.Fatalf("good credit failed: %s%s", good100.Stdout, good100.Stderr)
	}
	wantSub(t, "credit", good100.Stdout, "100.00")
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin, env: good}, "bank", "100", "--ref", "UTR-1"); r.ExitCode == 0 {
		t.Errorf("replayed bank reference was credited twice")
	}
	rc := e2eJSON(t, "/v1/reconcile")
	if rc["reserve"].(float64) != 100.0 || rc["deposit_count"].(float64) != 1 {
		t.Fatalf("reconcile after first credit: %v", rc)
	}

	e2eStep(t, 4, "Device identity: no quota => no proofs; operator allocates; denominated top-up")
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "credit-dummy"); r.ExitCode == 0 {
		t.Errorf("unknown subcommand accepted")
	}
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin, env: good}, "bank", "400", "--ref", "UTR-2"); r.ExitCode != 0 {
		t.Fatalf("second bank credit failed: %s%s", r.Stdout, r.Stderr)
	}
	devOut := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "device")
	pkDev := e2eDeviceKeyRe.FindStringSubmatch(devOut.Stdout)
	if pkDev == nil {
		t.Fatalf("no device key in: %s", devOut.Stdout)
	}
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "topup", "10"); r.ExitCode == 0 {
		t.Errorf("a device with no allocation got proofs")
	}
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "allocate", pkDev[1], "300", "--ref", "ALLOC-1"); r.ExitCode == 0 {
		t.Errorf("allocation without the operator secret was accepted")
	}
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin, env: good}, "allocate", pkDev[1], "300", "--ref", "ALLOC-1"); r.ExitCode != 0 {
		t.Fatalf("good allocate failed: %s%s", r.Stdout, r.Stderr)
	}
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin, env: good}, "allocate", pkDev[1], "300", "--ref", "ALLOC-1"); r.ExitCode == 0 {
		t.Errorf("replayed allocation ref was accepted")
	}
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin, env: good}, "allocate", pkDev[1], "9999", "--ref", "ALLOC-2"); r.ExitCode == 0 {
		t.Errorf("allocation above the reserve was accepted")
	}
	r237 := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "topup", "237")
	if r237.ExitCode != 0 {
		t.Fatalf("topup 237 failed: %s%s", r237.Stdout, r237.Stderr)
	}
	wantSub(t, "topup", r237.Stdout, "topup +237")
	if bal := balanceOfVault(t, p, pin, "alice"); bal != 237 {
		t.Errorf("alice balance = %d, want 237", bal)
	}
	ksRaw, _ := json.Marshal(e2eJSON(t, "/v1/keysets"))
	if !strings.Contains(string(ksRaw), "go-mvp-d200") {
		t.Errorf("keysets do not include go-mvp-d200: %s", ksRaw)
	}
	rc = e2eJSON(t, "/v1/reconcile")
	if rc["issued_outstanding"].(float64) != 237 || rc["fully_backed"].(bool) != true || rc["ledger_consistent"].(bool) != true {
		t.Fatalf("reconcile after topup: %v", rc)
	}

	e2eStep(t, "4b", "Exact payment, then change-making via /v1/swap")
	r37 := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "pay", "37")
	tok37 := lastLine(r37)
	if tokenValue(t, tok37) != 37 {
		t.Errorf("token value: got %d want 37", tokenValue(t, tok37))
	}
	if bal := balanceOfVault(t, p, pin, "alice"); bal != 200 {
		t.Errorf("alice balance after pay 37 = %d, want 200", bal)
	}
	r40 := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "pay", "40") // only a 200 left: must swap
	if tokenValue(t, lastLine(r40)) != 40 {
		t.Errorf("token after swap value: want 40")
	}
	if bal := balanceOfVault(t, p, pin, "alice"); bal != 160 {
		t.Errorf("alice balance after pay 40 = %d, want 160", bal)
	}
	if st := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "status"); strings.Contains(st.Stdout, "PENDING") {
		t.Errorf("status shows PENDING swap")
	}
	rBob := p.e2eVault("bob", e2eOpt{t: t, tls: "pin", pin: pin}, "receive", tok37)
	wantSub(t, "bob receive", rBob.Stdout, "received +4 proofs")
	sBob := p.e2eVault("bob", e2eOpt{t: t, tls: "pin", pin: pin}, "settle", tok37)
	if got := strings.Count(sBob.Stdout, "SETTLED OK"); got != 4 {
		t.Errorf("bob settle: %d SETTLED OK, want 4\n%s", got, sBob.Stdout)
	}
	sAlice := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "settle", lastLine(r40))
	if got := strings.Count(sAlice.Stdout, "SETTLED OK"); got != 2 {
		t.Errorf("alice settle of change: %d SETTLED OK, want 2\n%s", got, sAlice.Stdout)
	}
	rc = e2eJSON(t, "/v1/reconcile")
	if rc["issued_outstanding"].(float64) != 160 || rc["fully_backed"].(bool) != true {
		t.Fatalf("reconcile after settles: %v", rc)
	}
	_ = p.e2eVault("bob", e2eOpt{t: t, tls: "pin", pin: pin}, "wipe")

	e2eStep(t, 5, "Real P2PK: proofs locked to Charlie's ed25519 key at issuance")
	keyOut := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "keygen")
	pkChar := e2ePubKeyRe.FindStringSubmatch(keyOut.Stdout)
	skChar := e2eSecretKeyRe.FindStringSubmatch(keyOut.Stdout)
	if pkChar == nil || skChar == nil {
		t.Fatalf("keygen output: %s", keyOut.Stdout)
	}
	tl := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "topup", "2", "--lock", pkChar[1])
	wantSub(t, "topup --lock", tl.Stdout, "topup +2")
	if bal := balanceOfVault(t, p, pin, "alice"); bal != 162 {
		t.Errorf("alice balance after locked topup = %d, want 162", bal)
	}
	tokChar := lastLine(p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "pay", "2", "--p2pk", pkChar[1]))
	if bal := balanceOfVault(t, p, pin, "alice"); bal != 160 {
		t.Errorf("alice balance after locked pay = %d, want 160", bal)
	}
	res := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "verify", tokChar)
	if !strings.Contains(res.Stdout, "VERIFIED: 1 valid proof(s)") || !strings.Contains(res.Stdout, pkChar[1]) {
		t.Errorf("offline verify: %s", res.Stdout)
	}

	// No claim key / wrong key / relabelled / inflated: all refused.
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "settle", tokChar); r.ExitCode == 0 {
		t.Errorf("locked proof settled without claim key")
	} else {
		wantSubErr(t, "settle no-claim", r, "SETTLE REJECTED")
	}
	keyThief := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "keygen")
	skThief := e2eSecretKeyRe.FindStringSubmatch(keyThief.Stdout)
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "settle", tokChar, "--claim-key", skThief[1]); r.ExitCode == 0 {
		t.Errorf("locked proof settled with the wrong claim key")
	}
	clean := strings.TrimRight(tokChar, "=")
	raw, _ := base64.RawURLEncoding.DecodeString(clean)
	var proofs []map[string]any
	json.Unmarshal(raw, &proofs)
	for _, pr := range proofs {
		delete(pr, "p2pk")
		pr["claimer"] = pkChar[1]
		pr["p2pk"] = pkChar[1]
	}
	relabel, _ := json.Marshal(proofs)
	relabelled := base64.RawURLEncoding.EncodeToString([]byte(relabel))
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "settle", relabelled); r.ExitCode == 0 {
		t.Errorf("relabelled token settled: lock fields are not trusted")
	} else {
		wantSubErr(t, "settle relabelled", r, "SETTLE REJECTED")
	}
	for _, pr := range proofs {
		pr["keyset_id"] = "go-mvp-d500"
	}
	inflated, _ := json.Marshal(proofs)
	inflatedTok := base64.RawURLEncoding.EncodeToString([]byte(inflated))
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "verify", inflatedTok); r.ExitCode == 0 {
		t.Errorf("denomination relabel (inflation) accepted")
	}
	res = p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "settle", tokChar, "--claim-key", skChar[1])
	if got := strings.Count(res.Stdout, "SETTLED OK"); got != 1 {
		t.Errorf("charlie claim settle: %d SETTLED OK, want 1\n%s", got, res.Stdout)
	}

	e2eStep(t, 6, "Double-spend replay rejected; outbox keeps the emitted tokens")
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "settle", tokChar, "--claim-key", skChar[1]); r.ExitCode == 0 {
		t.Errorf("replayed proof settled twice")
	} else {
		wantSubErr(t, "replay settle", r, "SETTLE REJECTED")
	}
	out := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "outbox")
	if !strings.Contains(out.Stdout, tokChar) {
		t.Errorf("emitted token missing from outbox:\n%s", out.Stdout)
	}
	ack := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "ack", "1")
	wantSub(t, "ack", ack.Stdout, "outbox entry 1 acknowledged")

	e2eStep(t, 7, "Peer-to-peer offline hand-over to Bob")
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "topup", "1"); r.ExitCode != 0 {
		t.Fatalf("topup 1: %s%s", r.Stdout, r.Stderr)
	}
	tokBob := lastLine(p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "pay", "1"))
	rBob = p.e2eVault("bob", e2eOpt{t: t, tls: "pin", pin: pin}, "receive", tokBob)
	wantSub(t, "bob receive small", rBob.Stdout, "received +1 proofs")
	if bal := balanceOfVault(t, p, pin, "bob"); bal != 1 {
		t.Errorf("bob balance = %d, want 1", bal)
	}
	sBob = p.e2eVault("bob", e2eOpt{t: t, tls: "pin", pin: pin}, "settle", tokBob)
	wantSub(t, "bob settle", sBob.Stdout, "SETTLED OK")

	e2eStep(t, 8, "Forged tokens are rejected (fake modulus, e=1)")
	forge := func(kw map[string]any) string {
		base := map[string]any{"secret": "fupi-counterfeit-cash-e2e", "sig": "AQIDBAU=",
			"e": 65537, "keyset_id": "go-mvp-00"}
		for k, v := range kw {
			base[k] = v
		}
		list, _ := json.Marshal([]any{base})
		return base64.RawURLEncoding.EncodeToString(list)
	}
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "verify", forge(map[string]any{"n": "FAKE_MODULUS_N"})); r.ExitCode == 0 {
		t.Errorf("forged modulus accepted")
	}
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "verify", forge(map[string]any{"e": 1})); r.ExitCode == 0 {
		t.Errorf("e=1 forgery accepted")
	}

	e2eStep(t, 9, "5 concurrent settles of one token: exactly one winner")
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "topup", "1"); r.ExitCode != 0 {
		t.Fatalf("topup for race: %s%s", r.Stdout, r.Stderr)
	}
	race := lastLine(p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "pay", "1"))
	var mu sync.Mutex
	winners := 0
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "settle", race)
			if r.ExitCode == 0 {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Errorf("settle race winners = %d, want exactly 1", winners)
	}

	e2eStep(t, 10, "Merchant terminal: accept offline, refuse replays, batch settle, catch a double-spend")
	pinOut := p.e2eVault("shop", e2eOpt{t: t, tls: "pin", pin: pin}, "pin")
	wantSub(t, "shop pin", pinOut.Stdout, "Pinned keyset")
	t37 := lastLine(p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "pay", "37"))
	res = p.e2eVault("shop", e2eOpt{t: t, tls: "pin", pin: pin}, "accept", t37, "--invoice", "INV-1", "--expect", "37")
	wantSub(t, "accept INV-1", res.Stdout, "ACCEPTED receipt #1 amount=37")
	for _, extra := range [][]string{{"--expect", "37"}, {}} {
		full := append([]string{"accept", t37}, extra...)
		r := p.e2eVault("shop", e2eOpt{t: t, tls: "pin", pin: pin}, full...)
		if r.ExitCode != 2 {
			t.Errorf("replayed token accepted (exit %d)", r.ExitCode)
		} else {
			wantSubErr(t, "replay accept", r, "REJECTED")
		}
	}
	t20 := lastLine(p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "pay", "20"))
	r := p.e2eVault("shop", e2eOpt{t: t, tls: "pin", pin: pin}, "accept", t20, "--expect", "25")
	if r.ExitCode != 2 {
		t.Errorf("accept with wrong --expect passed (exit=%d): %s", r.ExitCode, res.Stdout)
	} else {
		wantSubErr(t, "wrong amount accept", r, "Wrong amount")
	}
	if bal := balanceOfVault(t, p, pin, "shop"); bal != 37 {
		t.Errorf("shop held = %d, want 37", bal)
	}
	res = p.e2eVault("shop", e2eOpt{t: t, tls: "pin", pin: pin}, "accept", t20, "--invoice", "INV-2")
	wantSub(t, "accept INV-2", res.Stdout, "ACCEPTED receipt #2 amount=20")
	t10 := lastLine(p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "pay", "10"))
	res = p.e2eVault("shop", e2eOpt{t: t, tls: "pin", pin: pin}, "accept", t10, "--invoice", "INV-3")
	wantSub(t, "accept INV-3", res.Stdout, "ACCEPTED receipt #3 amount=10")
	// Alice settles the 20 herself before the shop does (offline double-spend).
	sA := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "settle", t20)
	if got := strings.Count(sA.Stdout, "SETTLED OK"); got < 1 {
		t.Errorf("alice settle-all-before-shop: %d, want >=1\n%s", got, sA.Stdout)
	}
	r = p.e2eVault("shop", e2eOpt{t: t, tls: "pin", pin: pin}, "settle-all", "--merchant", "cafe-7")
	if r.ExitCode != 2 {
		t.Errorf("settle-all with double-spent receipt exit=%d, want 2", r.ExitCode)
	}
	wantSubErr(t, "settle-all totals", r, "SETTLED value=47 rejected=20 still_held=0")
	rcpts := p.e2eVault("shop", e2eOpt{t: t, tls: "pin", pin: pin}, "receipts")
	for _, ln := range []string{
		"invoice=INV-1 amount=37 settled=37 rejected=0 pending=0",
		"invoice=INV-2 amount=20 settled=0 rejected=20 pending=0",
		"invoice=INV-3 amount=10 settled=10 rejected=0 pending=0",
	} {
		if !strings.Contains(rcpts.Stdout, ln) {
			t.Errorf("receipts missing %q in:\n%s", ln, rcpts.Stdout)
		}
	}

	e2eStep(t, 11, "Cash-out: operator report, bank payout recorded, replay and overpay refused")
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "report"); r.ExitCode == 0 {
		t.Errorf("report without the operator secret succeeded")
	}
	rep := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin, env: good}, "report")
	repAll := rep.Stdout
	for _, ln := range []string{
		"cafe-7: settled=47 paid=0 OWED=47 (5 proofs)",
		"merchant=cafe-7 amount=20 keyset=go-mvp-d20",
		"merchant=cafe-7 amount=2 keyset=go-mvp-d2",
		"merchant=(unlabeled)",
	} {
		if !strings.Contains(repAll, ln) {
			t.Errorf("report missing %q in:\n%s", ln, repAll)
		}
	}
	rc0 := e2eJSON(t, "/v1/reconcile")
	if rc0["owed_total"].(float64) != rc0["settled_total"].(float64) || rc0["fully_backed"].(bool) != true {
		t.Fatalf("reconcile pre-payout: %v", rc0)
	}
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin, env: good}, "payout", "cafe-7", "100", "--ref", "UTR-P1"); r.ExitCode == 0 {
		t.Errorf("overpay accepted")
	}
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, "payout", "cafe-7", "40", "--ref", "UTR-P2"); r.ExitCode == 0 {
		t.Errorf("payout without the operator secret succeeded")
	}
	res = p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin, env: good}, "payout", "cafe-7", "40", "--ref", "UTR-P2")
	wantSub(t, "payout", res.Stdout, "PAYOUT RECORDED merchant=cafe-7 paid=40 owed=7")
	if r := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin, env: good}, "payout", "cafe-7", "7", "--ref", "UTR-P2"); r.ExitCode == 0 {
		t.Errorf("replayed payout reference accepted")
	}
	rc1 := e2eJSON(t, "/v1/reconcile")
	if rc1["reserve"].(float64) != rc0["reserve"].(float64)-40.0 || rc1["paid_total"].(float64) != 40.0 {
		t.Errorf("reconcile post-payout: rc0=%v rc1=%v", rc0, rc1)
	}
	if rc1["fully_backed"].(bool) != true || rc1["ledger_consistent"].(bool) != true {
		t.Errorf("reconcile post-payout not consistent: %v", rc1)
	}
	repMerch := p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin, env: good}, "report", "--merchant", "cafe-7")
	wantSub(t, "merchant report", repMerch.Stdout, "cafe-7: settled=47 paid=40 OWED=7")

	e2eStep(t, 12, "Pilot daily check against the live kiosk (go run ./pilot)")
	_ = os.Remove(p.log)
	reserveNow := e2eJSON(t, "/v1/reconcile")["reserve"].(float64)
	pilot := func(t *testing.T, bank string, secret bool, pinOverride string) e2eResult {
		t.Helper()
		args := []string{"run", "./pilot", "--atm", e2eURL}
		if pinOverride != "" {
			args = append(args, "--pin-tls", pinOverride)
		} else {
			args = append(args, "--pin-tls", pin)
		}
		if bank != "" {
			args = append(args, "--bank-balance", bank)
		}
		args = append(args, "--max-total", "500", "--log", p.log)
		cmd := exec.Command("go", args...)
		cmd.Dir = filepath.Join(p.root, "kiosk-go")
		env := e2eBaseEnv()
		if secret {
			env = append(env, "FUPI_CREDIT_SECRET="+e2eCredit)
		}
		cmd.Env = env
		var so, se bytes.Buffer
		cmd.Stdout, cmd.Stderr = &so, &se
		err := cmd.Run()
		exit := 0
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("pilot run failed to start: %v\n%s%s", err, so.String(), se.String())
		}
		return e2eResult{Stdout: so.String(), Stderr: se.String(), ExitCode: exit}
	}
	r = pilot(t, fmt.Sprintf("%v", reserveNow), true, "")
	if r.ExitCode != 0 {
		t.Errorf("first pilot run failed (exit %d):\n%s%s", r.ExitCode, r.Stdout, r.Stderr)
	}
	wantSub(t, "pilot pass", r.Stdout, "RESULT: PASS")
	wantSub(t, "pilot cross-check", r.Stdout, "settlement log sums to")
	r = pilot(t, fmt.Sprintf("%v", reserveNow), true, "")
	if r.ExitCode != 0 {
		t.Errorf("second pilot run failed:\n%s%s", r.Stdout, r.Stderr)
	}
	wantSub(t, "pilot day-over-day", r.Stdout, "explained")
	r = pilot(t, fmt.Sprintf("%v", reserveNow-1), true, "")
	if r.ExitCode != 1 {
		t.Errorf("pilot with bank BELOW reserve did not fail loudly (exit %d)", r.ExitCode)
	}
	wantSubErr(t, "pilot below-reserve", r, "BELOW reserve")
	r = pilot(t, "", false, e2eBadPinHex)
	if r.ExitCode == 0 {
		t.Errorf("pilot accepted a wrong TLS pin")
	}
	wantSubErr(t, "pilot wrong pin", r, "does not match")
	_ = os.Remove(p.log)

	// Final sanity: the whole bookkeeping still adds up, and the kiosk's
	// outstanding equals alice's remaining wallet exactly.
	rc = e2eJSON(t, "/v1/reconcile")
	if rc["fully_backed"].(bool) != true || rc["ledger_consistent"].(bool) != true {
		t.Errorf("final reconcile: %v", rc)
	}
	balAlice := balanceOfVault(t, p, pin, "alice")
	if issued := rc["issued_outstanding"].(float64); issued != float64(balAlice) {
		t.Errorf("issued %v != alice balance %d (unbacked or lost money)", issued, balAlice)
	}
	t.Logf("Final reconcile: %v", rc)
}

// r0Of re-runs a command for its full stdout (used where the Python kept res).
func r0Of(t *testing.T, p e2ePaths, pin, sub string, args ...string) string {
	t.Helper()
	return p.e2eVault("alice", e2eOpt{t: t, tls: "pin", pin: pin}, append([]string{sub}, args...)...).Stdout
}

// balanceOfVault runs `balance` and parses the integer.
func balanceOfVault(t *testing.T, p e2ePaths, pin, who string) int {
	t.Helper()
	r := p.e2eVault(who, e2eOpt{t: t, tls: "pin", pin: pin}, "balance")
	n, err := strconv.Atoi(strings.TrimSpace(r.Stdout))
	if err != nil {
		t.Fatalf("balance of %s not an integer: %q (stderr %s)", who, r.Stdout, r.Stderr)
	}
	return n
}
