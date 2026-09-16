package main

import (
	"fmt"
	"math/big"
	"testing"
)

// TestSettleMath reproduces the exact Python-vault flow in-process:
// blind -> BlindSign -> unblind -> Settle. Isolates HTTP/encoding from math.
func TestSettleMath(t *testing.T) {
	k, err := NewKiosk("")
	if err != nil {
		t.Fatal(err)
	}
	k.CreditReserve(10)

	secret := []byte("cross-lang-token-001")
	m := hashToScalar(secret, k.key.N)

	r := big.NewInt(3) // gcd(3, N)=1 since N is odd
	e := big.NewInt(int64(k.key.PublicKey.E))
	mB := new(big.Int).Mul(m, new(big.Int).Exp(r, e, k.key.N))
	mB.Mod(mB, k.key.N)

	sigB64, err := k.BlindSign(b64(mB.Bytes()), 1)
	if err != nil {
		t.Fatal(err)
	}
	s := new(big.Int).SetBytes(mustUnb64(sigB64))

	sig := new(big.Int).Mul(s, new(big.Int).ModInverse(r, k.key.N))
	sig.Mod(sig, k.key.N)

	if chk := new(big.Int).Exp(sig, e, k.key.N); chk.Cmp(m) != 0 {
		t.Fatalf("client-side verify failed: chk=%v m=%v", chk, m)
	}

	ok, msg := k.Settle(Proof{Secret: string(secret), Sig: b64(sig.Bytes())})
	if !ok {
		t.Fatalf("settle rejected: %s", msg)
	}
	if ok, _ := k.Settle(Proof{Secret: string(secret), Sig: b64(sig.Bytes())}); ok {
		t.Fatal("replay accepted!")
	}
}

func TestInvalidBase64DoesNotPanic(t *testing.T) {
	k, err := NewKiosk("")
	if err != nil {
		t.Fatal(err)
	}
	k.CreditReserve(10)

	// Invalid base64 to BlindSign
	_, err = k.BlindSign("not_valid_base64!!!", 1)
	if err == nil {
		t.Fatal("expected error on invalid base64 in BlindSign")
	}

	// Invalid base64 in Settle
	ok, msg := k.Settle(Proof{Secret: "some-secret", Sig: "not_valid_base64@@@"})
	if ok {
		t.Fatal("expected settlement to be rejected for invalid signature base64")
	}
	if msg == "" {
		t.Fatal("expected error message")
	}

	// Empty secret in Settle
	ok, _ = k.Settle(Proof{Secret: "", Sig: b64([]byte("sig"))})
	if ok {
		t.Fatal("expected settlement to be rejected for empty secret")
	}
}

func TestConcurrentDoubleSpendRace(t *testing.T) {
	k, err := NewKiosk("")
	if err != nil {
		t.Fatal(err)
	}
	k.CreditReserve(100)

	secret := []byte("race-test-token-001")
	m := hashToScalar(secret, k.key.N)
	r := big.NewInt(7)
	e := big.NewInt(int64(k.key.PublicKey.E))
	mB := new(big.Int).Mul(m, new(big.Int).Exp(r, e, k.key.N))
	mB.Mod(mB, k.key.N)

	sigB64, err := k.BlindSign(b64(mB.Bytes()), 1)
	if err != nil {
		t.Fatal(err)
	}
	s := new(big.Int).SetBytes(mustUnb64(sigB64))
	sig := new(big.Int).Mul(s, new(big.Int).ModInverse(r, k.key.N))
	sig.Mod(sig, k.key.N)

	proof := Proof{Secret: string(secret), Sig: b64(sig.Bytes())}

	const goroutines = 50
	results := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			ok, _ := k.Settle(proof)
			results <- ok
		}()
	}

	successCount := 0
	rejectCount := 0
	for i := 0; i < goroutines; i++ {
		if <-results {
			successCount++
		} else {
			rejectCount++
		}
	}

	if successCount != 1 {
		t.Fatalf("expected exactly 1 successful settlement under concurrent race, got %d", successCount)
	}
	if rejectCount != goroutines-1 {
		t.Fatalf("expected %d rejections, got %d", goroutines-1, rejectCount)
	}
}

func BenchmarkBlindSignSettle(b *testing.B) {
	k, err := NewKiosk("")
	if err != nil {
		b.Fatal(err)
	}
	k.CreditReserve(float64(b.N + 1))
	e := big.NewInt(int64(k.key.PublicKey.E))
	r := big.NewInt(3)
	rInv := new(big.Int).ModInverse(r, k.key.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		secret := []byte(fmt.Sprintf("bench-token-%d", i))
		m := hashToScalar(secret, k.key.N)
		mB := new(big.Int).Mul(m, new(big.Int).Exp(r, e, k.key.N))
		mB.Mod(mB, k.key.N)
		sigB64, err := k.BlindSign(b64(mB.Bytes()), 1)
		if err != nil {
			b.Fatal(err)
		}
		s := new(big.Int).SetBytes(mustUnb64(sigB64))
		sig := new(big.Int).Mod(new(big.Int).Mul(s, rInv), k.key.N)
		if ok, msg := k.Settle(Proof{Secret: string(secret), Sig: b64(sig.Bytes())}); !ok {
			b.Fatal(msg)
		}
	}
}

