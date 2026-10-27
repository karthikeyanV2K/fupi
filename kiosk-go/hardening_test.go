package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// signSecret runs the full client side of the blind protocol in-process and
// returns the unblinded signature (base64url) for secret.
func signSecret(t *testing.T, k *Kiosk, secret string) string {
	t.Helper()
	n := k.key.N
	e := big.NewInt(int64(k.key.PublicKey.E))
	m := hashToScalar([]byte(secret), n)
	r := big.NewInt(3)
	mB := new(big.Int).Mod(new(big.Int).Mul(m, new(big.Int).Exp(r, e, n)), n)
	sbB64, err := k.BlindSign(b64(mB.Bytes()), 1)
	if err != nil {
		t.Fatalf("blind sign: %v", err)
	}
	sb := new(big.Int).SetBytes(mustUnb64(sbB64))
	sig := new(big.Int).Mod(new(big.Int).Mul(sb, new(big.Int).ModInverse(r, n)), n)
	return b64(sig.Bytes())
}

func creditReq(t *testing.T, mux *http.ServeMux, secret, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/credit", strings.NewReader(body))
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(body))
		req.Header.Set("X-Fupi-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestCreditRequiresAuthAndUniqueRef(t *testing.T) {
	k, _ := NewKiosk("")
	mux := SetupMux(k, false, "")
	body := `{"amount":100,"ref":"UTR-1"}`

	// No secret configured: endpoint is disabled, nothing can be credited.
	if rr := creditReq(t, mux, "s3cret", body); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled endpoint: want 503, got %d", rr.Code)
	}

	k.SetCreditSecret("s3cret")
	if rr := creditReq(t, mux, "", body); rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing signature: want 401, got %d", rr.Code)
	}
	if rr := creditReq(t, mux, "wrong", body); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong signature: want 401, got %d", rr.Code)
	}
	if k.Reconcile().Reserve != 0 {
		t.Fatal("unauthenticated credit changed the reserve")
	}

	if rr := creditReq(t, mux, "s3cret", body); rr.Code != http.StatusOK {
		t.Fatalf("valid credit: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	// Replay of the same bank reference must not inflate the reserve.
	if rr := creditReq(t, mux, "s3cret", body); rr.Code != http.StatusConflict {
		t.Fatalf("replayed ref: want 409, got %d", rr.Code)
	}
	if got := k.Reconcile().Reserve; got != 100 {
		t.Fatalf("reserve after replay = %v, want 100", got)
	}
	// Missing ref and bad amounts are rejected.
	for _, b := range []string{`{"amount":5}`, `{"amount":-1,"ref":"x"}`, `{"amount":0,"ref":"y"}`} {
		if rr := creditReq(t, mux, "s3cret", b); rr.Code != http.StatusBadRequest {
			t.Fatalf("body %s: want 400, got %d", b, rr.Code)
		}
	}
}

func TestReconcileTracksLedgerAndIssuance(t *testing.T) {
	k, _ := NewKiosk("")
	k.SetCreditSecret("s")
	if _, err := k.Deposit("A", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Deposit("B", 5); err != nil {
		t.Fatal(err)
	}
	signSecret(t, k, "fupi-r1")
	signSecret(t, k, "fupi-r2")
	rc := k.Reconcile()
	if rc.Reserve != 15 || rc.DepositsTotal != 15 || rc.DepositCount != 2 || rc.IssuedOutstand != 2 {
		t.Fatalf("unexpected reconcile: %+v", rc)
	}
	if !rc.FullyBacked || !rc.LedgerConsistent {
		t.Fatalf("should be backed and consistent: %+v", rc)
	}
}

func TestBlindSignRejectsUnsupportedDenominations(t *testing.T) {
	k, _ := NewKiosk("")
	k.CreditReserve(100)
	for _, amt := range []int{0, 3, 1000, -1, int(^uint(0) >> 1)} {
		if _, err := k.BlindSign("Ag", amt); err == nil {
			t.Fatalf("amount %d accepted", amt)
		}
	}
	if k.Reconcile().IssuedOutstand != 0 {
		t.Fatal("rejected sign requests must not change issued")
	}
}

func TestLockedProofNeedsClaimSignature(t *testing.T) {
	k, _ := NewKiosk("")
	k.CreditReserve(10)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	secret := "fupi-locked-0001|lock=" + hex.EncodeToString(pub)
	sig := signSecret(t, k, secret)

	// No claim, wrong claim, garbage claim: all rejected.
	if ok, _ := k.Settle(Proof{Secret: secret, Sig: sig}); ok {
		t.Fatal("locked proof settled without a claim signature")
	}
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	bad := hex.EncodeToString(ed25519.Sign(otherPriv, []byte(secret)))
	if ok, _ := k.Settle(Proof{Secret: secret, Sig: sig, Claimer: bad}); ok {
		t.Fatal("locked proof settled with another key's signature")
	}
	// Legacy label tricks no longer work: copying the lock into claimer/p2pk is useless.
	if ok, _ := k.Settle(Proof{Secret: secret, Sig: sig, P2PK: hex.EncodeToString(pub), Claimer: hex.EncodeToString(pub)}); ok {
		t.Fatal("label-copy bypass worked")
	}
	// Stripping the lock changes the secret, which invalidates the mint signature.
	stripped := strings.SplitN(secret, "|lock=", 2)[0]
	if ok, _ := k.Settle(Proof{Secret: stripped, Sig: sig}); ok {
		t.Fatal("stripping the lock produced a spendable proof")
	}
	// The rightful owner succeeds exactly once.
	good := hex.EncodeToString(ed25519.Sign(priv, []byte(secret)))
	if ok, msg := k.Settle(Proof{Secret: secret, Sig: sig, Claimer: good}); !ok {
		t.Fatalf("owner claim rejected: %s", msg)
	}
	if ok, _ := k.Settle(Proof{Secret: secret, Sig: sig, Claimer: good}); ok {
		t.Fatal("replay accepted")
	}
}

func TestMalformedLockRejected(t *testing.T) {
	k, _ := NewKiosk("")
	k.CreditReserve(10)
	secret := "fupi-bad-lock|lock=zzzz"
	sig := signSecret(t, k, secret)
	if ok, _ := k.Settle(Proof{Secret: secret, Sig: sig}); ok {
		t.Fatal("malformed lock accepted")
	}
}

func TestCorruptStateNeverRegeneratesKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	k1, err := NewKiosk(path)
	if err != nil {
		t.Fatal(err)
	}
	origN := new(big.Int).Set(k1.key.N)
	if _, err := k1.Deposit("D1", 7); err != nil { // second save => .bak holds the first good state
		t.Fatal(err)
	}

	// Main file corrupted (e.g. torn write): recover from .bak with the SAME key.
	if err := os.WriteFile(path, []byte("{garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	k2, err := NewKiosk(path)
	if err != nil {
		t.Fatalf("expected recovery from .bak, got %v", err)
	}
	if k2.key.N.Cmp(origN) != 0 {
		t.Fatal("recovery generated a different key")
	}

	// Everything corrupted: refuse to start instead of minting a new key.
	for _, p := range []string{path, path + ".bak", path + ".tmp"} {
		if _, err := os.Stat(p); err == nil {
			if err := os.WriteFile(p, []byte("{garbage"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := NewKiosk(path); err == nil {
		t.Fatal("kiosk started with only corrupt state files; it must refuse")
	}
}

func TestLedgerSurvivesRestartAndStaysDeduped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	k1, _ := NewKiosk(path)
	if _, err := k1.Deposit("UTR-9", 50); err != nil {
		t.Fatal(err)
	}
	k2, err := NewKiosk(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k2.Deposit("UTR-9", 50); err != ErrDupRef {
		t.Fatalf("ref replay after restart: got %v, want ErrDupRef", err)
	}
	if rc := k2.Reconcile(); rc.Reserve != 50 || !rc.LedgerConsistent {
		t.Fatalf("bad ledger after restart: %+v", rc)
	}
}

func TestLegacyStateGetsOpeningBalance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	k1, _ := NewKiosk(path)
	k1.CreditReserve(20)
	// Simulate a pre-ledger state file: reserve present, no deposits.
	st, err := readState(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Deposits = nil
	k2 := &Kiosk{spent: map[string]struct{}{}, depositRefs: map[string]struct{}{}}
	if err := k2.applyState(st); err != nil {
		t.Fatal(err)
	}
	if rc := k2.Reconcile(); rc.DepositsTotal != 20 || !rc.LedgerConsistent {
		t.Fatalf("legacy reserve not booked: %+v", rc)
	}
}

func hmacHex(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
