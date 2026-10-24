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
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
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

// Deposit is one inbound bank/rail credit. The ledger is append-only and every
// deposit carries a unique external reference (bank UTR, webhook order id, ...),
// so replaying the same payment can never inflate the reserve.
type Deposit struct {
	Ref    string  `json:"ref"`
	Amount float64 `json:"amount"`
	At     string  `json:"at"`
}

var (
	ErrBadRef    = errors.New("ref required (1-128 chars)")
	ErrBadAmount = errors.New("amount must be > 0 and finite")
	ErrDupRef    = errors.New("duplicate deposit reference")
)

// Denominations the kiosk signs (money units). Denomination 1 keeps the legacy
// key and keyset id "go-mvp-00" so existing state and tokens keep working.
var Denominations = []int{1, 2, 5, 10, 20, 50, 100, 200, 500}

const legacyKeysetID = "go-mvp-00"

func isDenomination(a int) bool {
	for _, d := range Denominations {
		if d == a {
			return true
		}
	}
	return false
}

func keysetIDFor(amount int) string {
	if amount == 1 {
		return legacyKeysetID
	}
	return fmt.Sprintf("go-mvp-d%d", amount)
}

// amountForKeyset maps a proof's keyset id to its face value. The value is ALWAYS
// derived from the keyset the mint signed with, never from a client-supplied field.
func amountForKeyset(id string) (int, bool) {
	if id == "" || id == legacyKeysetID {
		return 1, true
	}
	if strings.HasPrefix(id, "go-mvp-d") {
		if n, err := strconv.Atoi(id[len("go-mvp-d"):]); err == nil && isDenomination(n) {
			return n, true
		}
	}
	return 0, false
}

type KeysetInfo struct {
	KeysetID string `json:"keyset_id"`
	Amount   int    `json:"amount"`
	N        string `json:"n"`
	E        int    `json:"e"`
}

// Device is a vault identified by an ed25519 public key. The operator allocates it a
// quota (money units); every issuance request must be signed by the device with a
// strictly increasing sequence number, and cannot exceed the allocation.
type Device struct {
	Allocated float64 `json:"allocated"`
	Loaded    int     `json:"loaded"`
	LastSeq   uint64  `json:"last_seq"`
}

var (
	ErrBadDeviceSig  = errors.New("bad device signature")
	ErrBadDevice     = errors.New("device must be a 32-byte ed25519 public key in hex")
	ErrUnknownDevice = errors.New("device has no quota: operator must allocate first")
	ErrDeviceReplay  = errors.New("stale or replayed device sequence number")
	ErrQuota         = errors.New("device quota exceeded")
	ErrOverAllocated = errors.New("allocation exceeds reserve")
)

const maxSwapCache = 2000

type Kiosk struct {
	mu           sync.Mutex
	key          *rsa.PrivateKey // denomination 1 (legacy keyset go-mvp-00)
	keys         map[int]*rsa.PrivateKey
	reserve      float64
	issued       int // money units outstanding
	spent        map[string]struct{}
	deposits     []Deposit
	depositRefs  map[string]struct{}
	devices      map[string]*Device
	allocRefs    map[string]struct{}
	swapCache    map[string][]string // idempotency: request hash -> signatures
	swapOrder    []string
	allowAnon    bool
	creditSecret []byte
	statePath    string
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
	k := &Kiosk{
		keys:        map[int]*rsa.PrivateKey{},
		spent:       map[string]struct{}{},
		depositRefs: map[string]struct{}{},
		devices:     map[string]*Device{},
		allocRefs:   map[string]struct{}{},
		swapCache:   map[string][]string{},
		statePath:   statePath,
	}
	loaded, err := k.loadState()
	if err != nil {
		// State exists but is unreadable: NEVER mint a fresh key over it, that
		// would destroy the signing key and the double-spend set.
		return nil, err
	}
	if !loaded {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		k.key = key
		k.keys[1] = key
		if err := k.saveState(); err != nil {
			return nil, err
		}
	}
	return k, nil
}

// EnsureDenominations generates any missing per-denomination signing keys and
// persists them. NewKiosk only guarantees denomination 1, so tests stay fast.
func (k *Kiosk) EnsureDenominations() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	changed := false
	for _, d := range Denominations {
		if k.keys[d] != nil {
			continue
		}
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		k.keys[d] = key
		changed = true
		log.Printf("[kiosk] generated signing key for denomination %d", d)
	}
	if changed {
		return k.saveState()
	}
	return nil
}

func (k *Kiosk) SetAllowAnonymous(v bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.allowAnon = v
}

func (k *Kiosk) AnonymousAllowed() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.allowAnon
}

// SetCreditSecret configures the HMAC secret that authenticates /v1/credit.
// Empty secret = credit endpoint disabled.
func (k *Kiosk) SetCreditSecret(s string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.creditSecret = []byte(s)
}

func (k *Kiosk) CreditEnabled() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.creditSecret) > 0
}

// VerifyCreditAuth checks hex(HMAC-SHA256(secret, rawBody)) in constant time.
func (k *Kiosk) VerifyCreditAuth(rawBody []byte, sigHex string) bool {
	k.mu.Lock()
	secret := k.creditSecret
	k.mu.Unlock()
	if len(secret) == 0 {
		return false
	}
	got, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(rawBody)
	return hmac.Equal(mac.Sum(nil), got)
}

// Deposit records a verified inbound payment and raises the reserve. ref must
// be unique; a repeated ref is rejected (ErrDupRef) and changes nothing.
func (k *Kiosk) Deposit(ref string, amount float64) (float64, error) {
	if ref == "" || len(ref) > 128 {
		return 0, ErrBadRef
	}
	if !(amount > 0) || math.IsInf(amount, 0) || amount > 1e12 {
		return 0, ErrBadAmount
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, dup := k.depositRefs[ref]; dup {
		return k.reserve, ErrDupRef
	}
	oldReserve := k.reserve
	k.deposits = append(k.deposits, Deposit{Ref: ref, Amount: amount, At: time.Now().UTC().Format(time.RFC3339)})
	k.depositRefs[ref] = struct{}{}
	k.reserve += amount
	if err := k.saveState(); err != nil {
		k.deposits = k.deposits[:len(k.deposits)-1]
		delete(k.depositRefs, ref)
		k.reserve = oldReserve
		return oldReserve, err
	}
	log.Printf("[kiosk] deposit ref=%s +%.2f (reserve %.2f)", ref, amount, k.reserve)
	return k.reserve, nil
}

// CreditReserve is a local/test convenience that records a deposit with a
// random reference. It is NOT reachable over HTTP.
func (k *Kiosk) CreditReserve(amount float64) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	if _, err := k.Deposit("local-"+hex.EncodeToString(b[:]), amount); err != nil {
		log.Printf("[kiosk] CreditReserve failed: %v", err)
	}
}

// Reconcile summarises whether outstanding tokens are covered by the reserve
// and whether the deposit ledger adds up to it.
type Reconcile struct {
	Reserve          float64 `json:"reserve"`
	IssuedOutstand   int     `json:"issued_outstanding"`
	DepositsTotal    float64 `json:"deposits_total"`
	DepositCount     int     `json:"deposit_count"`
	SettledCount     int     `json:"settled_count"`
	DevicesAllocated float64 `json:"devices_allocated"`
	DevicesLoaded    int     `json:"devices_loaded"`
	FullyBacked      bool    `json:"fully_backed"`
	LedgerConsistent bool    `json:"ledger_consistent"`
}

func (k *Kiosk) Reconcile() Reconcile {
	k.mu.Lock()
	defer k.mu.Unlock()
	var total, alloc float64
	var loaded int
	for _, d := range k.deposits {
		total += d.Amount
	}
	for _, d := range k.devices {
		alloc += d.Allocated
		loaded += d.Loaded
	}
	return Reconcile{
		Reserve:          k.reserve,
		IssuedOutstand:   k.issued,
		DepositsTotal:    total,
		DepositCount:     len(k.deposits),
		SettledCount:     len(k.spent),
		DevicesAllocated: alloc,
		DevicesLoaded:    loaded,
		FullyBacked:      float64(k.issued) <= k.reserve+1e-9,
		LedgerConsistent: math.Abs(total-k.reserve) < 1e-6,
	}
}

// Keysets lists the public key of every denomination the kiosk can sign.
func (k *Kiosk) Keysets() []KeysetInfo {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []KeysetInfo
	for _, d := range Denominations {
		if key := k.keys[d]; key != nil {
			out = append(out, KeysetInfo{KeysetID: keysetIDFor(d), Amount: d, N: b64(key.N.Bytes()), E: key.E})
		}
	}
	return out
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
		Version:        "0.3.0",
		KeysetID:       "go-mvp-00",
		Reserve:        k.reserve,
		Issued:         k.issued,
		SpentCount:     len(k.spent),
		TLSEnabled:     tlsEnabled,
		TLSFingerprint: fingerprint,
	}
}

// blindSignNoSave signs a blinded scalar under the key of denomination `amount`
// and counts `amount` as issued. Caller holds k.mu, then persists or rolls back.
// The kiosk NEVER sees the token secret. Textbook RSA on the blinded value is
// exactly Chaum's scheme: PKCS#1 padding would defeat the blinding.
func (k *Kiosk) blindSignNoSave(blindedB64 string, amount int) (string, error) {
	key := k.keys[amount]
	if key == nil {
		return "", fmt.Errorf("unsupported denomination %d", amount)
	}
	if float64(k.issued+amount) > k.reserve {
		return "", fmt.Errorf("insufficient reserve (1:1 rule)")
	}
	raw, err := unb64(blindedB64)
	if err != nil {
		return "", fmt.Errorf("invalid base64 blinded_message: %w", err)
	}
	mB := new(big.Int).SetBytes(raw)
	if mB.Sign() <= 0 || mB.Cmp(key.N) >= 0 {
		return "", fmt.Errorf("blinded scalar out of valid range [1, N)")
	}
	sB := new(big.Int).Exp(mB, key.D, key.N)
	k.issued += amount
	return b64(sB.Bytes()), nil
}

// BlindSign is the un-authenticated issuance path (local/dev/tests; over HTTP it is only
// reachable with -allow-anonymous-issuance). The signature is only released after the
// new state is persisted.
func (k *Kiosk) BlindSign(blindedB64 string, amount int) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	sig, err := k.blindSignNoSave(blindedB64, amount)
	if err != nil {
		return "", err
	}
	if err := k.saveState(); err != nil {
		k.issued -= amount
		return "", fmt.Errorf("could not persist issuance: %w", err)
	}
	return sig, nil
}

func normDevice(deviceHex string) (string, ed25519.PublicKey, error) {
	d := strings.ToLower(strings.TrimSpace(deviceHex))
	b, err := hex.DecodeString(d)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return "", nil, ErrBadDevice
	}
	return d, ed25519.PublicKey(b), nil
}

// DeviceSignMessage is exactly what a device signs to request one proof.
func DeviceSignMessage(device string, seq uint64, amount int, blindedB64 string) string {
	return fmt.Sprintf("fupi-blind-sign-v1|%s|%d|%d|%s", device, seq, amount, blindedB64)
}

// AllocateDevice (operator action) gives a device quota. ref must be unique so a replayed
// allocation request cannot double the quota; total allocations can never exceed the reserve.
func (k *Kiosk) AllocateDevice(deviceHex string, amount float64, ref string) (float64, error) {
	dev, _, err := normDevice(deviceHex)
	if err != nil {
		return 0, err
	}
	if ref == "" || len(ref) > 128 {
		return 0, ErrBadRef
	}
	if !(amount > 0) || math.IsInf(amount, 0) || amount > 1e12 {
		return 0, ErrBadAmount
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, dup := k.allocRefs[ref]; dup {
		return 0, ErrDupRef
	}
	var total float64
	for _, d := range k.devices {
		total += d.Allocated
	}
	if total+amount > k.reserve+1e-9 {
		return 0, ErrOverAllocated
	}
	d := k.devices[dev]
	isNew := d == nil
	if isNew {
		d = &Device{}
		k.devices[dev] = d
	}
	d.Allocated += amount
	k.allocRefs[ref] = struct{}{}
	if err := k.saveState(); err != nil {
		d.Allocated -= amount
		if isNew {
			delete(k.devices, dev)
		}
		delete(k.allocRefs, ref)
		return 0, err
	}
	log.Printf("[kiosk] allocated %.2f to device %s.. (total %.2f)", amount, dev[:8], d.Allocated)
	return d.Allocated, nil
}

// SignForDevice issues one proof of `amount` to an allocated device. The request must be
// signed by the device key with a strictly increasing seq, and stay within its quota.
func (k *Kiosk) SignForDevice(deviceHex string, seq uint64, amount int, blindedB64, sigHex string) (string, error) {
	dev, pub, err := normDevice(deviceHex)
	if err != nil {
		return "", err
	}
	sig, derr := hex.DecodeString(strings.TrimSpace(sigHex))
	if derr != nil || !ed25519.Verify(pub, []byte(DeviceSignMessage(dev, seq, amount, blindedB64)), sig) {
		return "", ErrBadDeviceSig
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	d := k.devices[dev]
	if d == nil {
		return "", ErrUnknownDevice
	}
	if seq <= d.LastSeq {
		return "", ErrDeviceReplay
	}
	if amount <= 0 || float64(d.Loaded+amount) > d.Allocated+1e-9 {
		return "", ErrQuota
	}
	out, err := k.blindSignNoSave(blindedB64, amount)
	if err != nil {
		return "", err
	}
	oldSeq := d.LastSeq
	d.LastSeq = seq
	d.Loaded += amount
	if err := k.saveState(); err != nil {
		k.issued -= amount
		d.LastSeq = oldSeq
		d.Loaded -= amount
		return "", fmt.Errorf("could not persist issuance: %w", err)
	}
	return out, nil
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

// lockOf parses an optional "|lock=<ed25519 pubkey hex>" suffix of a secret.
// The lock lives INSIDE the blind-signed secret, so it cannot be stripped or
// rewritten after issuance without invalidating the mint's signature.
func lockOf(secret string) (pub ed25519.PublicKey, locked bool, err error) {
	i := strings.Index(secret, "|lock=")
	if i < 0 {
		return nil, false, nil
	}
	b, derr := hex.DecodeString(secret[i+len("|lock="):])
	if derr != nil || len(b) != ed25519.PublicKeySize {
		return nil, true, fmt.Errorf("malformed lock")
	}
	return ed25519.PublicKey(b), true, nil
}

// checkProofLocked verifies a proof against the key of ITS OWN denomination and returns
// its face value, or a rejection reason. Caller holds k.mu.
func (k *Kiosk) checkProofLocked(p Proof) (int, string) {
	if p.Secret == "" {
		return 0, "REJECTED: empty secret"
	}
	if len(p.Secret) > 256 {
		return 0, "REJECTED: secret too long"
	}
	amount, ok := amountForKeyset(p.KeysetID)
	key := k.keys[amount]
	if !ok || key == nil {
		return 0, "REJECTED: unknown keyset"
	}
	if _, dup := k.spent[p.Secret]; dup {
		return 0, "REJECTED: double-spend (already settled)"
	}
	sigBytes, err := unb64(p.Sig)
	if err != nil {
		return 0, "REJECTED: invalid signature base64"
	}
	s := new(big.Int).SetBytes(sigBytes)
	if s.Sign() <= 0 || s.Cmp(key.N) >= 0 {
		return 0, "REJECTED: signature scalar out of range"
	}
	m := hashToScalar([]byte(p.Secret), key.N)
	if new(big.Int).Exp(s, big.NewInt(int64(key.PublicKey.E)), key.N).Cmp(m) != 0 {
		return 0, "REJECTED: bad signature"
	}
	return amount, ""
}

// Settle redeems a proof for its face value. If the secret carries a lock, Claimer must be
// the hex ed25519 signature over the secret bytes by that key. The legacy P2PK field is
// ignored: it was an unauthenticated label and gave no security.
func (k *Kiosk) Settle(p Proof) (bool, string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	amount, reason := k.checkProofLocked(p)
	if reason != "" {
		return false, reason
	}
	lockPub, locked, lerr := lockOf(p.Secret)
	if lerr != nil {
		return false, "REJECTED: malformed lock"
	}
	if locked {
		claim, derr := hex.DecodeString(strings.TrimSpace(p.Claimer))
		if derr != nil || !ed25519.Verify(lockPub, []byte(p.Secret), claim) {
			return false, "REJECTED: P2PK lock (invalid claim signature)"
		}
	}
	k.spent[p.Secret] = struct{}{}
	oldIssued := k.issued
	k.issued -= amount
	if k.issued < 0 {
		k.issued = 0
	}
	if err := k.saveState(); err != nil {
		delete(k.spent, p.Secret)
		k.issued = oldIssued
		return false, "REJECTED: could not persist settlement"
	}
	return true, fmt.Sprintf("settled OK %d (first-to-settle-wins)", amount)
}

type SwapOut struct {
	BlindedMessage string `json:"blinded_message"`
	Amount         int    `json:"amount"`
}

func swapKey(inputs []Proof, outputs []SwapOut) string {
	secrets := make([]string, len(inputs))
	for i, p := range inputs {
		secrets[i] = p.Secret
	}
	sort.Strings(secrets)
	h := sha256.New()
	for _, s := range secrets {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	h.Write([]byte{1})
	for _, o := range outputs {
		fmt.Fprintf(h, "%d:%s\x00", o.Amount, o.BlindedMessage)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Swap exchanges unlocked proofs for fresh blind-signed proofs of the same TOTAL value
// (change-making: 500 -> 200+200+100, or 50 -> 20+20+10). Issued money is unchanged.
//
// It is idempotent: an identical request (same inputs, same blinded outputs) returns the
// SAME signatures, so a client that crashed after the kiosk spent its inputs can re-send
// the request and recover its outputs instead of losing the value.
func (k *Kiosk) Swap(inputs []Proof, outputs []SwapOut) ([]string, error) {
	if len(inputs) == 0 || len(inputs) > 64 || len(outputs) == 0 || len(outputs) > 64 {
		return nil, errors.New("swap needs 1-64 inputs and 1-64 outputs")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	ck := swapKey(inputs, outputs)
	if sigs, ok := k.swapCache[ck]; ok {
		return append([]string(nil), sigs...), nil
	}

	seen := map[string]struct{}{}
	sumIn := 0
	for _, p := range inputs {
		if _, dup := seen[p.Secret]; dup {
			return nil, errors.New("REJECTED: duplicate input in swap")
		}
		seen[p.Secret] = struct{}{}
		amount, reason := k.checkProofLocked(p)
		if reason != "" {
			return nil, errors.New(reason)
		}
		if _, locked, lerr := lockOf(p.Secret); locked || lerr != nil {
			return nil, errors.New("REJECTED: locked proofs must be settled by their owner, not swapped")
		}
		sumIn += amount
	}
	sumOut := 0
	sigs := make([]string, len(outputs))
	for i, o := range outputs {
		key := k.keys[o.Amount]
		if key == nil {
			return nil, fmt.Errorf("unsupported output denomination %d", o.Amount)
		}
		raw, err := unb64(o.BlindedMessage)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 blinded_message: %w", err)
		}
		mB := new(big.Int).SetBytes(raw)
		if mB.Sign() <= 0 || mB.Cmp(key.N) >= 0 {
			return nil, errors.New("blinded scalar out of valid range [1, N)")
		}
		sigs[i] = b64(new(big.Int).Exp(mB, key.D, key.N).Bytes())
		sumOut += o.Amount
	}
	if sumIn != sumOut {
		return nil, fmt.Errorf("swap not balanced: inputs %d, outputs %d", sumIn, sumOut)
	}

	for _, p := range inputs {
		k.spent[p.Secret] = struct{}{}
	}
	k.swapCache[ck] = sigs
	k.swapOrder = append(k.swapOrder, ck)
	var evicted []string
	var evictedSigs [][]string
	for len(k.swapOrder) > maxSwapCache {
		old := k.swapOrder[0]
		evicted = append(evicted, old)
		evictedSigs = append(evictedSigs, k.swapCache[old])
		k.swapOrder = k.swapOrder[1:]
		delete(k.swapCache, old)
	}
	if err := k.saveState(); err != nil {
		for _, p := range inputs {
			delete(k.spent, p.Secret)
		}
		delete(k.swapCache, ck)
		k.swapOrder = k.swapOrder[:len(k.swapOrder)-1]
		for i, old := range evicted {
			k.swapCache[old] = evictedSigs[i]
		}
		k.swapOrder = append(evicted, k.swapOrder...)
		return nil, errors.New("could not persist swap")
	}
	return append([]string(nil), sigs...), nil
}

// ---- persistence (survives restarts) ----
// Write path: state -> .tmp (fsync) -> copy last GOOD state to .bak -> rename.
// Load path: main, then .tmp, then .bak. If any state file exists but none is
// valid we refuse to start, rather than silently generating a new key.

type diskDenom struct {
	Amount int    `json:"amount"`
	N      string `json:"n"`
	D      string `json:"d"`
}

type diskState struct {
	N         string              `json:"n"` // denomination 1 (legacy keyset)
	D         string              `json:"d"`
	Denoms    []diskDenom         `json:"denoms,omitempty"` // every other denomination
	Reserve   float64             `json:"reserve"`
	Issued    int                 `json:"issued"`
	Spent     []string            `json:"spent"`
	Deposits  []Deposit           `json:"deposits,omitempty"`
	Devices   map[string]*Device  `json:"devices,omitempty"`
	AllocRefs []string            `json:"alloc_refs,omitempty"`
	SwapCache map[string][]string `json:"swap_cache,omitempty"`
	SwapOrder []string            `json:"swap_order,omitempty"`
}

func readState(path string) (*diskState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st diskState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	if st.N == "" || st.D == "" {
		return nil, errors.New("missing key material")
	}
	return &st, nil
}

func (k *Kiosk) saveState() error {
	if k.statePath == "" {
		return nil
	}
	st := diskState{
		N:         b64(k.key.N.Bytes()),
		D:         b64(k.key.D.Bytes()),
		Reserve:   k.reserve,
		Issued:    k.issued,
		Deposits:  k.deposits,
		Devices:   k.devices,
		SwapCache: k.swapCache,
		SwapOrder: k.swapOrder,
	}
	for _, d := range Denominations {
		if d == 1 || k.keys[d] == nil {
			continue
		}
		st.Denoms = append(st.Denoms, diskDenom{Amount: d, N: b64(k.keys[d].N.Bytes()), D: b64(k.keys[d].D.Bytes())})
	}
	for s := range k.spent {
		st.Spent = append(st.Spent, s)
	}
	for r := range k.allocRefs {
		st.AllocRefs = append(st.AllocRefs, r)
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
	// Keep the last known-good state as .bak (never overwrite it with a corrupt file).
	if _, err := readState(k.statePath); err == nil {
		if prev, rerr := os.ReadFile(k.statePath); rerr == nil {
			_ = os.WriteFile(k.statePath+".bak", prev, 0600)
		}
	}
	return os.Rename(tmpPath, k.statePath)
}

// parseKey rebuilds an RSA key from (n, d) and proves it is a working pair: (2^d)^e == 2 (mod n).
func parseKey(nB64, dB64 string) (*rsa.PrivateKey, error) {
	nBytes, errN := unb64(nB64)
	dBytes, errD := unb64(dB64)
	if errN != nil || errD != nil {
		return nil, fmt.Errorf("corrupt key encoding")
	}
	n := new(big.Int).SetBytes(nBytes)
	d := new(big.Int).SetBytes(dBytes)
	if n.Sign() <= 0 || d.Sign() <= 0 {
		return nil, fmt.Errorf("invalid key material")
	}
	two := big.NewInt(2)
	if new(big.Int).Exp(new(big.Int).Exp(two, d, n), big.NewInt(65537), n).Cmp(two) != 0 {
		return nil, fmt.Errorf("key pair self-check failed")
	}
	return &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: 65537}, D: d}, nil
}

func (k *Kiosk) applyState(st *diskState) error {
	key, err := parseKey(st.N, st.D)
	if err != nil {
		return err
	}
	keys := map[int]*rsa.PrivateKey{1: key}
	for _, dd := range st.Denoms {
		if !isDenomination(dd.Amount) || dd.Amount == 1 {
			return fmt.Errorf("bad denomination %d in state", dd.Amount)
		}
		dk, err := parseKey(dd.N, dd.D)
		if err != nil {
			return fmt.Errorf("denomination %d: %w", dd.Amount, err)
		}
		keys[dd.Amount] = dk
	}
	k.key = key
	k.keys = keys
	k.reserve, k.issued = st.Reserve, st.Issued
	k.spent = map[string]struct{}{}
	for _, s := range st.Spent {
		k.spent[s] = struct{}{}
	}
	k.deposits = append([]Deposit(nil), st.Deposits...)
	k.depositRefs = map[string]struct{}{}
	var sum float64
	for _, d := range k.deposits {
		k.depositRefs[d.Ref] = struct{}{}
		sum += d.Amount
	}
	// State written before the ledger existed: book the gap as an opening balance.
	if gap := k.reserve - sum; gap > 1e-9 {
		k.deposits = append(k.deposits, Deposit{Ref: "legacy-opening-balance", Amount: gap, At: time.Now().UTC().Format(time.RFC3339)})
		k.depositRefs["legacy-opening-balance"] = struct{}{}
	}
	k.devices = map[string]*Device{}
	for id, d := range st.Devices {
		if d != nil {
			cp := *d
			k.devices[id] = &cp
		}
	}
	k.allocRefs = map[string]struct{}{}
	for _, r := range st.AllocRefs {
		k.allocRefs[r] = struct{}{}
	}
	k.swapCache = map[string][]string{}
	for h, sigs := range st.SwapCache {
		k.swapCache[h] = append([]string(nil), sigs...)
	}
	k.swapOrder = append([]string(nil), st.SwapOrder...)
	return nil
}

func (k *Kiosk) loadState() (bool, error) {
	if k.statePath == "" {
		return false, nil
	}
	anyExists := false
	var firstErr error
	for _, p := range []string{k.statePath, k.statePath + ".tmp", k.statePath + ".bak"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		anyExists = true
		st, err := readState(p)
		if err == nil {
			err = k.applyState(st)
		}
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", p, err)
			}
			log.Printf("[kiosk] state file %s unusable: %v", p, err)
			continue
		}
		if p != k.statePath {
			log.Printf("[kiosk] RECOVERED state from %s (last operation may be lost)", p)
			if err := k.saveState(); err != nil {
				return false, err
			}
		}
		log.Printf("[kiosk] state loaded: reserve=%.2f issued=%d spent=%d deposits=%d denominations=%d devices=%d",
			k.reserve, k.issued, len(k.spent), len(k.deposits), len(k.keys), len(k.devices))
		return true, nil
	}
	if anyExists {
		return false, fmt.Errorf("state file(s) exist but none are valid; refusing to create a new key: %v", firstErr)
	}
	return false, nil
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

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	return json.NewDecoder(r.Body).Decode(v) == nil
}

// authedBody reads a size-limited body and checks its HMAC (operator-only endpoints).
func (k *Kiosk) authedBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if !k.CreditEnabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "operator endpoints disabled: set -credit-secret or FUPI_CREDIT_SECRET"})
		return nil, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad request"})
		return nil, false
	}
	if !k.VerifyCreditAuth(raw, r.Header.Get("X-Fupi-Signature")) {
		writeJSON(w, 401, map[string]string{"error": "bad or missing X-Fupi-Signature"})
		return nil, false
	}
	return raw, true
}

func SetupMux(k *Kiosk, tlsEnabled bool, fingerprint string) *http.ServeMux {
	mux := http.NewServeMux()

	getOnly := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return false
		}
		return true
	}
	postOnly := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return false
		}
		return true
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/atm" {
			http.NotFound(w, r)
			return
		}
		if !getOnly(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		dashTmpl.Execute(w, k.Info(tlsEnabled, fingerprint))
	})

	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		if getOnly(w, r) {
			writeJSON(w, 200, k.Info(tlsEnabled, fingerprint))
		}
	})

	mux.HandleFunc("/v1/keyset", func(w http.ResponseWriter, r *http.Request) {
		if getOnly(w, r) {
			writeJSON(w, 200, k.Pubkey())
		}
	})

	mux.HandleFunc("/v1/reconcile", func(w http.ResponseWriter, r *http.Request) {
		if getOnly(w, r) {
			writeJSON(w, 200, k.Reconcile())
		}
	})

	// POST /v1/credit  body {"amount": <major units>, "ref": "<unique bank ref>"}
	// Header X-Fupi-Signature: hex(HMAC-SHA256(credit secret, raw body)).
	mux.HandleFunc("/v1/credit", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		if !k.CreditEnabled() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "credit endpoint disabled: set -credit-secret or FUPI_CREDIT_SECRET"})
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if !k.VerifyCreditAuth(raw, r.Header.Get("X-Fupi-Signature")) {
			writeJSON(w, 401, map[string]string{"error": "bad or missing X-Fupi-Signature"})
			return
		}
		var body struct {
			Amount float64 `json:"amount"`
			Ref    string  `json:"ref"`
		}
		if json.Unmarshal(raw, &body) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		reserve, err := k.Deposit(body.Ref, body.Amount)
		switch {
		case errors.Is(err, ErrDupRef):
			writeJSON(w, 409, map[string]string{"error": err.Error()})
		case errors.Is(err, ErrBadRef), errors.Is(err, ErrBadAmount):
			writeJSON(w, 400, map[string]string{"error": err.Error()})
		case err != nil:
			writeJSON(w, 500, map[string]string{"error": "could not persist deposit"})
		default:
			writeJSON(w, 200, map[string]float64{"reserve": reserve})
		}
	})

	mux.HandleFunc("/v1/keysets", func(w http.ResponseWriter, r *http.Request) {
		if getOnly(w, r) {
			writeJSON(w, 200, map[string]any{"keysets": k.Keysets()})
		}
	})

	// POST /v1/allocate  (operator, HMAC-authenticated like /v1/credit)
	// body {"device":"<ed25519 pubkey hex>","amount":N,"ref":"<unique>"}
	mux.HandleFunc("/v1/allocate", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		raw, ok := k.authedBody(w, r)
		if !ok {
			return
		}
		var body struct {
			Device string  `json:"device"`
			Amount float64 `json:"amount"`
			Ref    string  `json:"ref"`
		}
		if json.Unmarshal(raw, &body) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		total, err := k.AllocateDevice(body.Device, body.Amount, body.Ref)
		switch {
		case errors.Is(err, ErrDupRef):
			writeJSON(w, 409, map[string]string{"error": err.Error()})
		case errors.Is(err, ErrOverAllocated):
			writeJSON(w, 402, map[string]string{"error": err.Error()})
		case errors.Is(err, ErrBadDevice), errors.Is(err, ErrBadRef), errors.Is(err, ErrBadAmount):
			writeJSON(w, 400, map[string]string{"error": err.Error()})
		case err != nil:
			writeJSON(w, 500, map[string]string{"error": "could not persist allocation"})
		default:
			writeJSON(w, 200, map[string]float64{"allocated": total})
		}
	})

	mux.HandleFunc("/v1/blind-sign", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		var body struct {
			BlindedMessage string `json:"blinded_message"`
			Amount         int    `json:"amount"` // denomination
			Device         string `json:"device"`
			Seq            uint64 `json:"seq"`
			DeviceSig      string `json:"device_sig"`
		}
		if !decodeJSON(w, r, &body) || body.Amount <= 0 {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		var sig string
		var err error
		if body.Device == "" {
			if !k.AnonymousAllowed() {
				writeJSON(w, 401, map[string]string{"error": "device signature required"})
				return
			}
			sig, err = k.BlindSign(body.BlindedMessage, body.Amount)
		} else {
			sig, err = k.SignForDevice(body.Device, body.Seq, body.Amount, body.BlindedMessage, body.DeviceSig)
		}
		switch {
		case err == nil:
			writeJSON(w, 200, map[string]string{"blind_signature": sig})
		case errors.Is(err, ErrBadDeviceSig), errors.Is(err, ErrBadDevice):
			writeJSON(w, 401, map[string]string{"error": err.Error()})
		case errors.Is(err, ErrUnknownDevice):
			writeJSON(w, 403, map[string]string{"error": err.Error()})
		case errors.Is(err, ErrDeviceReplay):
			writeJSON(w, 409, map[string]string{"error": err.Error()})
		default: // quota, reserve, bad scalar, unsupported denomination
			writeJSON(w, 402, map[string]string{"error": err.Error()})
		}
	})

	// POST /v1/swap  {"inputs":[Proof...],"outputs":[{"blinded_message","amount"}...]}
	// -> {"signatures":[...]} in output order. Idempotent for an identical request.
	mux.HandleFunc("/v1/swap", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		var body struct {
			Inputs  []Proof   `json:"inputs"`
			Outputs []SwapOut `json:"outputs"`
		}
		if !decodeJSON(w, r, &body) {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		sigs, err := k.Swap(body.Inputs, body.Outputs)
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"signatures": sigs})
	})

	mux.HandleFunc("/v1/settle", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		var proof Proof
		if !decodeJSON(w, r, &proof) {
			writeJSON(w, 400, map[string]string{"error": "bad proof"})
			return
		}
		ok, msg := k.Settle(proof)
		code := 200
		if !ok {
			code = 409 // conflict: double-spend / bad sig / lock violation
		}
		writeJSON(w, code, map[string]string{"result": msg})
	})

	return mux
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}

func certFingerprint(c tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return ""
	}
	return fmt.Sprintf("%X", sha256.Sum256(c.Certificate[0]))
}

func main() {
	port := flag.Int("port", 8890, "listen port")
	statePath := flag.String("state", "kiosk_go_state.json", "state file")
	useTLS := flag.Bool("tls", true, "enable self-contained HTTPS / TLS")
	certFile := flag.String("cert", "", "custom TLS certificate PEM path (optional)")
	keyFile := flag.String("key", "", "custom TLS private key PEM path (optional)")
	saveCert := flag.Bool("save-cert", true, "save auto-generated TLS certificate to kiosk_cert.pem & kiosk_key.pem")
	forceNewCert := flag.Bool("force-new-cert", false, "force new TLS cert generation even if kiosk_cert.pem exists")
	creditSecret := flag.String("credit-secret", os.Getenv("FUPI_CREDIT_SECRET"),
		"HMAC secret authenticating POST /v1/credit (prefer env FUPI_CREDIT_SECRET). Empty = credit endpoint disabled")
	anon := flag.Bool("allow-anonymous-issuance", false,
		"DEV ONLY: accept /v1/blind-sign without a device signature (no per-device quota)")
	flag.Parse()

	k, err := NewKiosk(*statePath)
	if err != nil {
		log.Fatal(err)
	}
	if err := k.EnsureDenominations(); err != nil {
		log.Fatalf("could not prepare denomination keys: %v", err)
	}
	k.SetAllowAnonymous(*anon)
	if *anon {
		log.Printf("[kiosk-go] WARNING: anonymous issuance enabled (development only)")
	}
	k.SetCreditSecret(*creditSecret)
	if !k.CreditEnabled() {
		log.Printf("[kiosk-go] WARNING: no credit secret configured; /v1/credit is DISABLED (reserve cannot grow)")
	}

	addr := fmt.Sprintf(":%d", *port)

	if !*useTLS {
		log.Printf("[kiosk-go] FUPI ATM (Go) listening on http://%s (Plain HTTP, TLS disabled; do not expose publicly)", addr)
		log.Fatal(newServer(addr, SetupMux(k, false, "")).ListenAndServe())
	}

	var tlsCert tls.Certificate
	generate := func() {
		var certPEM, keyPEM []byte
		var gerr error
		tlsCert, certPEM, keyPEM, _, gerr = generateSelfSignedCert([]string{"127.0.0.1", "localhost"})
		if gerr != nil {
			log.Fatalf("failed to generate self-signed TLS cert: %v", gerr)
		}
		if *saveCert {
			_ = os.WriteFile("kiosk_cert.pem", certPEM, 0644)
			_ = os.WriteFile("kiosk_key.pem", keyPEM, 0600)
			log.Printf("[kiosk-go] auto-generated TLS cert saved to kiosk_cert.pem and kiosk_key.pem")
		}
	}

	switch {
	case *certFile != "" && *keyFile != "":
		tlsCert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("failed to load custom TLS cert/key: %v", err)
		}
		log.Printf("[kiosk-go] loaded custom TLS certificate from %s / %s", *certFile, *keyFile)
	case !*forceNewCert && fileExists("kiosk_cert.pem") && fileExists("kiosk_key.pem"):
		tlsCert, err = tls.LoadX509KeyPair("kiosk_cert.pem", "kiosk_key.pem")
		if err != nil {
			generate()
		} else {
			log.Printf("[kiosk-go] reused existing TLS certificate from kiosk_cert.pem and kiosk_key.pem")
		}
	default:
		generate()
	}
	fingerprint := certFingerprint(tlsCert)

	server := newServer(addr, SetupMux(k, true, fingerprint))
	server.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	log.Printf("[kiosk-go] FUPI Self-Contained HTTPS ATM listening on https://127.0.0.1%s", addr)
	log.Printf("[kiosk-go] TLS Fingerprint (SHA-256): %s", fingerprint)
	log.Fatal(server.ListenAndServeTLS("", ""))
}
