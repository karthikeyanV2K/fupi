package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// RSA keygen dominates test time, so generate the extra denomination keys once.
var (
	denomOnce sync.Once
	denomKeys map[int]*rsa.PrivateKey
)

func cachedDenomKeys(t *testing.T) map[int]*rsa.PrivateKey {
	denomOnce.Do(func() {
		denomKeys = map[int]*rsa.PrivateKey{}
		for _, d := range Denominations {
			if d == 1 {
				continue
			}
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			denomKeys[d] = key
		}
	})
	return denomKeys
}

func newDenomKiosk(t *testing.T) *Kiosk {
	t.Helper()
	k, err := NewKiosk("")
	if err != nil {
		t.Fatal(err)
	}
	for d, key := range cachedDenomKeys(t) {
		k.keys[d] = key
	}
	return k
}

// blindFor runs the client side of the protocol for one denomination and returns the proof.
// sign is called with the blinded scalar and must return the kiosk's blind signature.
func blindFor(t *testing.T, k *Kiosk, amount int, secret string, sign func(blinded string) (string, error)) Proof {
	t.Helper()
	key := k.keys[amount]
	m := hashToScalar([]byte(secret), key.N)
	r := big.NewInt(7)
	e := big.NewInt(int64(key.E))
	mB := new(big.Int).Mod(new(big.Int).Mul(m, new(big.Int).Exp(r, e, key.N)), key.N)
	sbB64, err := sign(b64(mB.Bytes()))
	if err != nil {
		t.Fatalf("sign %d: %v", amount, err)
	}
	sb := new(big.Int).SetBytes(mustUnb64(sbB64))
	sig := new(big.Int).Mod(new(big.Int).Mul(sb, new(big.Int).ModInverse(r, key.N)), key.N)
	return Proof{Secret: secret, Sig: b64(sig.Bytes()), KeysetID: keysetIDFor(amount)}
}

func anonSign(k *Kiosk, amount int) func(string) (string, error) {
	return func(b string) (string, error) { return k.BlindSign(b, amount) }
}

func TestKeysetIDMappingAndDenominations(t *testing.T) {
	if keysetIDFor(1) != "go-mvp-00" || keysetIDFor(50) != "go-mvp-d50" {
		t.Fatal("keyset id mapping changed")
	}
	for _, c := range []struct {
		id string
		a  int
		ok bool
	}{{"", 1, true}, {"go-mvp-00", 1, true}, {"go-mvp-d500", 500, true}, {"go-mvp-d3", 0, false}, {"go-mvp-dx", 0, false}, {"evil", 0, false}} {
		a, ok := amountForKeyset(c.id)
		if a != c.a || ok != c.ok {
			t.Fatalf("amountForKeyset(%q) = %d,%v want %d,%v", c.id, a, ok, c.a, c.ok)
		}
	}
	k := newDenomKiosk(t)
	if got := len(k.Keysets()); got != len(Denominations) {
		t.Fatalf("keysets = %d, want %d", got, len(Denominations))
	}
}

func TestDenominatedIssueAndSettleMoveMoney(t *testing.T) {
	k := newDenomKiosk(t)
	k.CreditReserve(1000)
	p5 := blindFor(t, k, 5, "fupi-d5-a", anonSign(k, 5))
	p200 := blindFor(t, k, 200, "fupi-d200-a", anonSign(k, 200))
	if k.Reconcile().IssuedOutstand != 205 {
		t.Fatalf("issued = %d, want 205", k.Reconcile().IssuedOutstand)
	}
	if ok, msg := k.Settle(p200); !ok || !strings.Contains(msg, "200") {
		t.Fatalf("settle 200: %v %s", ok, msg)
	}
	if k.Reconcile().IssuedOutstand != 5 {
		t.Fatalf("issued after settle = %d, want 5", k.Reconcile().IssuedOutstand)
	}
	// The value comes from the key that signed it: a 5-proof presented as a 500 is rejected.
	forged := p5
	forged.KeysetID = keysetIDFor(500)
	forged.Secret = "fupi-d5-a"
	if ok, _ := k.Settle(forged); ok {
		t.Fatal("5-unit proof settled as 500")
	}
	if ok, _ := k.Settle(Proof{Secret: p5.Secret, Sig: p5.Sig, KeysetID: "go-mvp-d3"}); ok {
		t.Fatal("unknown keyset accepted")
	}
	if ok, _ := k.Settle(p5); !ok {
		t.Fatal("legit 5 rejected")
	}
}

func TestIssuanceBoundByReserveInMoney(t *testing.T) {
	k := newDenomKiosk(t)
	k.CreditReserve(100)
	blindFor(t, k, 50, "fupi-r-1", anonSign(k, 50))
	blindFor(t, k, 50, "fupi-r-2", anonSign(k, 50))
	if _, err := k.BlindSign("Ag", 1); err == nil || !strings.Contains(err.Error(), "insufficient reserve") {
		t.Fatalf("issued past reserve: %v", err)
	}
	if _, err := k.BlindSign("Ag", 3); err == nil {
		t.Fatal("non-denomination accepted")
	}
}

func deviceKey(t *testing.T) (string, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub), priv
}

func devSign(priv ed25519.PrivateKey, dev string, seq uint64, amount int, blinded string) string {
	return hex.EncodeToString(ed25519.Sign(priv, []byte(DeviceSignMessage(dev, seq, amount, blinded))))
}

func TestDeviceQuotaSignaturesAndReplay(t *testing.T) {
	k := newDenomKiosk(t)
	k.CreditReserve(100)
	dev, priv := deviceKey(t)

	// Unknown device: valid signature but no quota.
	if _, err := k.SignForDevice(dev, 1, 5, "Ag", devSign(priv, dev, 1, 5, "Ag")); err != ErrUnknownDevice {
		t.Fatalf("unknown device: got %v", err)
	}
	if _, err := k.AllocateDevice(dev, 30, "A1"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.AllocateDevice(dev, 30, "A1"); err != ErrDupRef {
		t.Fatalf("replayed allocation: got %v", err)
	}
	_, otherPriv := deviceKey(t)

	// A signature by the wrong key is refused.
	if _, err := k.SignForDevice(dev, 1, 5, "Ag", devSign(otherPriv, dev, 1, 5, "Ag")); err != ErrBadDeviceSig {
		t.Fatalf("wrong key: got %v", err)
	}
	// A signature over different parameters (amount tampered) is refused.
	if _, err := k.SignForDevice(dev, 1, 20, "Ag", devSign(priv, dev, 1, 5, "Ag")); err != ErrBadDeviceSig {
		t.Fatalf("tampered amount: got %v", err)
	}

	blindFor(t, k, 20, "fupi-dev-1", func(b string) (string, error) {
		return k.SignForDevice(dev, 1, 20, b, devSign(priv, dev, 1, 20, b))
	})
	// Same sequence number again: replay.
	if _, err := k.SignForDevice(dev, 1, 5, "Ag", devSign(priv, dev, 1, 5, "Ag")); err != ErrDeviceReplay {
		t.Fatalf("seq replay: got %v", err)
	}
	// 20 loaded of 30: another 20 would exceed quota, 10 still fits.
	if _, err := k.SignForDevice(dev, 2, 20, "Ag", devSign(priv, dev, 2, 20, "Ag")); err != ErrQuota {
		t.Fatalf("quota: got %v", err)
	}
	blindFor(t, k, 10, "fupi-dev-2", func(b string) (string, error) {
		return k.SignForDevice(dev, 3, 10, b, devSign(priv, dev, 3, 10, b))
	})
	if rc := k.Reconcile(); rc.DevicesAllocated != 30 || rc.DevicesLoaded != 30 || rc.IssuedOutstand != 30 {
		t.Fatalf("reconcile: %+v", rc)
	}
}

func TestAllocationCannotExceedReserve(t *testing.T) {
	k := newDenomKiosk(t)
	k.CreditReserve(50)
	d1, _ := deviceKey(t)
	d2, _ := deviceKey(t)
	if _, err := k.AllocateDevice(d1, 40, "x1"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.AllocateDevice(d2, 20, "x2"); err != ErrOverAllocated {
		t.Fatalf("over-allocation: got %v", err)
	}
	if _, err := k.AllocateDevice("not-hex", 1, "x3"); err != ErrBadDevice {
		t.Fatalf("bad device: got %v", err)
	}
}

func TestHTTPBlindSignNeedsDeviceUnlessAnonymous(t *testing.T) {
	k := newDenomKiosk(t)
	k.CreditReserve(10)
	mux := SetupMux(k, false, "")
	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("POST", "/v1/blind-sign", strings.NewReader(body)))
		return rr
	}
	if rr := post(`{"blinded_message":"Ag","amount":1}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous blind-sign: want 401, got %d", rr.Code)
	}
	k.SetAllowAnonymous(true)
	if rr := post(`{"blinded_message":"Ag","amount":1}`); rr.Code != http.StatusOK {
		t.Fatalf("anonymous (dev flag): want 200, got %d %s", rr.Code, rr.Body.String())
	}
	k.SetAllowAnonymous(false)
	dev, _ := deviceKey(t)
	if rr := post(`{"blinded_message":"Ag","amount":1,"device":"` + dev + `","seq":1,"device_sig":"00"}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad device sig: want 401, got %d", rr.Code)
	}
}

func TestHTTPAllocateIsAuthenticated(t *testing.T) {
	k := newDenomKiosk(t)
	k.CreditReserve(10)
	k.SetCreditSecret("s3cret")
	mux := SetupMux(k, false, "")
	dev, _ := deviceKey(t)
	body := `{"device":"` + dev + `","amount":5,"ref":"alloc-1"}`
	do := func(secret string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/v1/allocate", strings.NewReader(body))
		if secret != "" {
			mac := sha256Hmac(secret, body)
			req.Header.Set("X-Fupi-Signature", mac)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	if rr := do(""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned allocate: want 401, got %d", rr.Code)
	}
	if rr := do("s3cret"); rr.Code != http.StatusOK {
		t.Fatalf("signed allocate: want 200, got %d %s", rr.Code, rr.Body.String())
	}
	if rr := do("s3cret"); rr.Code != http.StatusConflict {
		t.Fatalf("replayed allocate: want 409, got %d", rr.Code)
	}
}

func sha256Hmac(secret, body string) string {
	return hmacHex([]byte(secret), []byte(body))
}

func TestSwapMakesChangeAndIsIdempotent(t *testing.T) {
	k := newDenomKiosk(t)
	k.CreditReserve(1000)
	p50 := blindFor(t, k, 50, "fupi-swap-in", anonSign(k, 50))
	issuedBefore := k.Reconcile().IssuedOutstand

	// 50 -> 20 + 20 + 10: build blinded outputs the way the vault does.
	type outSpec struct {
		amount int
		secret string
	}
	specs := []outSpec{{20, "fupi-out-a"}, {20, "fupi-out-b"}, {10, "fupi-out-c"}}
	r := big.NewInt(11)
	var outs []SwapOut
	for _, sp := range specs {
		key := k.keys[sp.amount]
		m := hashToScalar([]byte(sp.secret), key.N)
		mB := new(big.Int).Mod(new(big.Int).Mul(m, new(big.Int).Exp(r, big.NewInt(int64(key.E)), key.N)), key.N)
		outs = append(outs, SwapOut{BlindedMessage: b64(mB.Bytes()), Amount: sp.amount})
	}
	sigs, err := k.Swap([]Proof{p50}, outs)
	if err != nil {
		t.Fatalf("swap: %v", err)
	}
	if k.Reconcile().IssuedOutstand != issuedBefore {
		t.Fatal("swap changed issued money")
	}
	// Retrying the identical request (client crashed after the kiosk spent its input)
	// returns the SAME signatures instead of "double-spend".
	again, err := k.Swap([]Proof{p50}, outs)
	if err != nil || strings.Join(again, ",") != strings.Join(sigs, ",") {
		t.Fatalf("retry not idempotent: %v", err)
	}
	// The outputs are real, spendable proofs worth 20, 20 and 10.
	total := 0
	for i, sp := range specs {
		key := k.keys[sp.amount]
		sb := new(big.Int).SetBytes(mustUnb64(sigs[i]))
		sig := new(big.Int).Mod(new(big.Int).Mul(sb, new(big.Int).ModInverse(r, key.N)), key.N)
		ok, _ := k.Settle(Proof{Secret: sp.secret, Sig: b64(sig.Bytes()), KeysetID: keysetIDFor(sp.amount)})
		if !ok {
			t.Fatalf("output %d not spendable", i)
		}
		total += sp.amount
	}
	if total != 50 {
		t.Fatal("outputs do not add up")
	}
	// The input is gone: settling it directly, or swapping it in a DIFFERENT request, fails.
	if ok, _ := k.Settle(p50); ok {
		t.Fatal("swapped input still settles")
	}
	if _, err := k.Swap([]Proof{p50}, outs[:1]); err == nil {
		t.Fatal("different request reusing a spent input was accepted")
	}
}

func TestSwapRejections(t *testing.T) {
	k := newDenomKiosk(t)
	k.CreditReserve(1000)
	p10 := blindFor(t, k, 10, "fupi-sw-1", anonSign(k, 10))
	dummy := func(amount int) SwapOut {
		key := k.keys[amount]
		return SwapOut{BlindedMessage: b64(new(big.Int).Mod(big.NewInt(12345), key.N).Bytes()), Amount: amount}
	}
	// Unbalanced.
	if _, err := k.Swap([]Proof{p10}, []SwapOut{dummy(20)}); err == nil {
		t.Fatal("unbalanced swap accepted")
	}
	// Duplicate input within one request.
	if _, err := k.Swap([]Proof{p10, p10}, []SwapOut{dummy(20)}); err == nil {
		t.Fatal("duplicate input accepted")
	}
	// Unknown output denomination.
	if _, err := k.Swap([]Proof{p10}, []SwapOut{{BlindedMessage: "Ag", Amount: 3}}); err == nil {
		t.Fatal("bad output denomination accepted")
	}
	// Forged input.
	bad := p10
	bad.Secret = "fupi-sw-forged"
	if _, err := k.Swap([]Proof{bad}, []SwapOut{dummy(10)}); err == nil {
		t.Fatal("forged input accepted")
	}
	// Locked proofs cannot be swapped (their owner must settle them).
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	locked := blindFor(t, k, 10, "fupi-locked-sw|lock="+hex.EncodeToString(pub), anonSign(k, 10))
	if _, err := k.Swap([]Proof{locked}, []SwapOut{dummy(10)}); err == nil {
		t.Fatal("locked proof swapped")
	}
	// Nothing above may have spent the legit input.
	if ok, _ := k.Settle(p10); !ok {
		t.Fatal("failed swaps must not consume inputs")
	}
}

func TestStateRoundTripKeepsDenominationsDevicesAndSwapCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	k1, err := NewKiosk(path)
	if err != nil {
		t.Fatal(err)
	}
	for d, key := range cachedDenomKeys(t) {
		k1.keys[d] = key
	}
	k1.CreditReserve(500)
	dev, _ := deviceKey(t)
	if _, err := k1.AllocateDevice(dev, 100, "a1"); err != nil {
		t.Fatal(err)
	}
	p := blindFor(t, k1, 20, "fupi-persist-in", anonSign(k1, 20))
	key := k1.keys[20]
	mB := new(big.Int).Mod(new(big.Int).Mul(hashToScalar([]byte("fupi-persist-out"), key.N),
		new(big.Int).Exp(big.NewInt(5), big.NewInt(int64(key.E)), key.N)), key.N)
	outs := []SwapOut{{BlindedMessage: b64(mB.Bytes()), Amount: 20}}
	sigs, err := k1.Swap([]Proof{p}, outs)
	if err != nil {
		t.Fatal(err)
	}

	k2, err := NewKiosk(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(k2.Keysets()) != len(Denominations) {
		t.Fatalf("denomination keys lost on restart: %d", len(k2.Keysets()))
	}
	if rc := k2.Reconcile(); rc.DevicesAllocated != 100 || rc.IssuedOutstand != 20 {
		t.Fatalf("restart reconcile: %+v", rc)
	}
	if _, err := k2.AllocateDevice(dev, 100, "a1"); err != ErrDupRef {
		t.Fatal("allocation ref replay possible after restart")
	}
	again, err := k2.Swap([]Proof{p}, outs)
	if err != nil || again[0] != sigs[0] {
		t.Fatalf("swap idempotency lost across restart: %v", err)
	}
}

func TestEnsureDenominationsGeneratesMissingKeysOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	k1, _ := NewKiosk(path)
	// Pre-seed all but one denomination to keep the test fast.
	for d, key := range cachedDenomKeys(t) {
		if d != 500 {
			k1.keys[d] = key
		}
	}
	if err := k1.EnsureDenominations(); err != nil {
		t.Fatal(err)
	}
	if k1.keys[500] == nil {
		t.Fatal("missing denomination not generated")
	}
	n500 := new(big.Int).Set(k1.keys[500].N)
	k2, err := NewKiosk(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := k2.EnsureDenominations(); err != nil {
		t.Fatal(err)
	}
	if k2.keys[500].N.Cmp(n500) != 0 {
		t.Fatal("EnsureDenominations replaced an existing key")
	}
}
