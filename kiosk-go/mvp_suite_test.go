// Package main — Go port of the retired mvp/test_mvp.py suite (FUPI MVP tests).
//
// The Python suite checked: blind-signature math, blinding unlinkability,
// reserve 1:1 rule, P2PK lock enforcement, double-spend rejection, offline
// verification. Those same verdicts are re-proven here against the REAL Go
// kiosk machinery (crypto primitives + Kiosk API), plus a minimal in-test
// wallet that mimics vault-rust semantics (denominated top-up, exact-subset
// payment, change via /v1/swap) so the wallet-flow checks are pure Go too.
// The real Rust vault is driven end-to-end in e2e_vault_test.go.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"
)

var mvpPass, mvpFail int

func mvpCheck(t *testing.T, name string, cond bool) {
	if cond {
		mvpPass++
		t.Logf("  PASS  %s", name)
	} else {
		mvpFail++
		t.Errorf("  FAIL  %s", name)
	}
}

func mvpReport(t *testing.T) {
	t.Logf("\n%d passed, %d failed (FUPI MVP port)", mvpPass, mvpFail)
	if mvpFail > 0 {
		t.Errorf("FUPI MVP port: %d check(s) FAILED", mvpFail)
	}
}

// ---- Chaum math (identical to the kiosk's scheme; textbook RSA by design) ----

func mvpHashToInt(secret []byte, n *big.Int) *big.Int {
	h := sha256SumBytes(secret)
	m := new(big.Int).SetBytes(h)
	m.Mod(m, n)
	if m.Cmp(big.NewInt(2)) < 0 { // clamp, like kiosk hashToScalar
		m.SetInt64(2)
	}
	return m
}

func mvpRandBlinder(t *testing.T, n *big.Int) *big.Int {
	t.Helper()
	for {
		r, err := rand.Int(rand.Reader, n)
		if err != nil {
			t.Fatal(err)
		}
		if r.Cmp(big.NewInt(16)) < 0 {
			continue
		}
		if g := new(big.Int).GCD(nil, nil, r, n); g.Cmp(big.NewInt(1)) == 0 {
			return r
		}
	}
}

// blind = (m · r^e) mod n
func mvpBlind(m, r *big.Int, pub *rsa.PublicKey) *big.Int {
	rb := new(big.Int).Exp(r, big.NewInt(int64(pub.E)), pub.N)
	return new(big.Int).Mod(new(big.Int).Mul(m, rb), pub.N)
}

// unblind = (s_blind · r^-1) mod n
func mvpUnblind(sBlind, r *big.Int, pub *rsa.PublicKey) *big.Int {
	ri := new(big.Int).ModInverse(r, pub.N)
	if ri == nil {
		return nil
	}
	return new(big.Int).Mod(new(big.Int).Mul(sBlind, ri), pub.N)
}

func mvpVerify(m, s *big.Int, pub *rsa.PublicKey) bool {
	return new(big.Int).Exp(s, big.NewInt(int64(pub.E)), pub.N).Cmp(m) == 0
}

func modScalar(t *testing.T, sigB64 string) *big.Int {
	t.Helper()
	raw, err := unb64(sigB64)
	if err != nil {
		t.Fatalf("bad signature encoding: %v", err)
	}
	return new(big.Int).SetBytes(raw)
}

func randHex16(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}

func sha256SumBytes(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// ---------------------------------------------------------------------------
// Tests 1 + 2: blind-signature roundtrip & blinding unlinkability
// ---------------------------------------------------------------------------

func TestMvp01BlindSignatureRoundtrip(t *testing.T) {
	defer mvpReport(t)
	kp, err := rsa.GenerateKey(rand.Reader, 1024) // math check only; the kiosk uses 2048
	if err != nil {
		t.Fatal(err)
	}
	secret := "fupi-test-secret-0001"
	m := mvpHashToInt([]byte(secret), kp.N)
	r := mvpRandBlinder(t, kp.N)
	sBlind := new(big.Int).Exp(mvpBlind(m, r, &kp.PublicKey), kp.D, kp.N) // the kiosk signs the blinded scalar
	s := mvpUnblind(sBlind, r, &kp.PublicKey)
	mvpCheck(t, "signature verifies after unblind", mvpVerify(m, s, &kp.PublicKey))
	mvpCheck(t, "kiosk never saw m (blinded view != message)", mvpBlind(m, r, &kp.PublicKey).Cmp(m) != 0)
}

func TestMvp02BlindingUnlinkability(t *testing.T) {
	defer mvpReport(t)
	// Blinding randomizes the KIOSK'S VIEW, not the final signature: same
	// message -> consistent unblinded sigs (deterministic RSA), but the blinded
	// values the kiosk signs are all different and unlinkable.
	kp, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	m := mvpHashToInt([]byte("unlink-test"), kp.N)
	var blindedViews, unblinded []*big.Int
	for i := 0; i < 4; i++ {
		r := mvpRandBlinder(t, kp.N)
		b := mvpBlind(m, r, &kp.PublicKey)
		blindedViews = append(blindedViews, b)
		sBlind := new(big.Int).Exp(b, kp.D, kp.N)
		unblinded = append(unblinded, mvpUnblind(sBlind, r, &kp.PublicKey))
	}
	distinct := true
	for i := range blindedViews {
		for j := i + 1; j < len(blindedViews); j++ {
			if blindedViews[i].Cmp(blindedViews[j]) == 0 {
				distinct = false
			}
		}
	}
	mvpCheck(t, "kiosk sees different blinded values each time", distinct)
	allValid := true
	for _, s := range unblinded {
		if !mvpVerify(m, s, &kp.PublicKey) {
			allValid = false
		}
	}
	mvpCheck(t, "unblinded sigs are all valid for m", allValid)
	allDiffers := true
	for _, b := range blindedViews {
		if b.Cmp(m) == 0 {
			allDiffers = false
		}
	}
	mvpCheck(t, "blinded view differs from raw message", allDiffers)
}

// ---------------------------------------------------------------------------
// Test 3: kiosk rules (reserve 1:1, settle, replay, forgery, P2PK) on the
// real Go kiosk.
// ---------------------------------------------------------------------------

func TestMvp03KioskRules(t *testing.T) {
	defer mvpReport(t)
	k, err := NewKiosk(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	pk := k.Pubkey()
	N := new(big.Int).SetBytes(mustUnb64(pk.N))

	k.CreditReserve(2)

	// 1:1 rule: signing a valuation bigger than the reserve must be refused.
	_, err = k.BlindSign(b64(big.NewInt(4).Bytes()), 5)
	mvpCheck(t, "1:1 reserve rule blocks overissue", err != nil)

	// Genuine proof -> settles once only; forgery refused.
	secret := "proof-a"
	m := mvpHashToInt([]byte(secret), N)
	r := mvpRandBlinder(t, N)
	sBlind, err := k.BlindSign(b64(mvpBlind(m, r, &k.key.PublicKey).Bytes()), 1)
	if err != nil {
		t.Fatalf("blind sign genuine: %v", err)
	}
	s := mvpUnblind(modScalar(t, sBlind), r, &k.key.PublicKey)
	proof := Proof{Secret: secret, Sig: b64(s.Bytes()), KeysetID: pk.KeysetID}
	ok, _ := k.Settle(proof)
	mvpCheck(t, "settle accepts genuine proof", ok)
	ok, _ = k.Settle(proof)
	mvpCheck(t, "settle rejects replay (double-spend)", !ok)

	bad := Proof{Secret: "forged", Sig: b64(new(big.Int).Add(s, big.NewInt(1)).Bytes()), KeysetID: pk.KeysetID}
	ok, _ = k.Settle(bad)
	mvpCheck(t, "settle rejects bad signature", !ok)

	// P2PK: in Go the lock lives INSIDE the blind-signed secret
	// ("|lock=<ed25519 pubkey hex>") and settlement requires a valid claim
	// signature — the hardened replacement of the Python demo's "p2pk" label.
	ownerPK, ownerSK, _ := ed25519.GenerateKey(rand.Reader)
	_, thiefSK, _ := ed25519.GenerateKey(rand.Reader)
	lockedSecret := "locked|lock=" + fmt.Sprintf("%x", ownerPK)
	m3 := mvpHashToInt([]byte(lockedSecret), N)
	r3 := mvpRandBlinder(t, N)
	sBlind3, err := k.BlindSign(b64(mvpBlind(m3, r3, &k.key.PublicKey).Bytes()), 1)
	if err != nil {
		t.Fatalf("blind sign locked: %v", err)
	}
	s3 := mvpUnblind(modScalar(t, sBlind3), r3, &k.key.PublicKey)
	rightClaim := fmt.Sprintf("%x", ed25519.Sign(ownerSK, []byte(lockedSecret)))
	wrongClaim := fmt.Sprintf("%x", ed25519.Sign(thiefSK, []byte(lockedSecret)))
	ok, _ = k.Settle(Proof{Secret: lockedSecret, Sig: b64(s3.Bytes()), KeysetID: pk.KeysetID, Claimer: wrongClaim})
	mvpCheck(t, "P2PK rejects wrong claimer", !ok)
	ok, _ = k.Settle(Proof{Secret: lockedSecret, Sig: b64(s3.Bytes()), KeysetID: pk.KeysetID, Claimer: rightClaim})
	mvpCheck(t, "P2PK accepts right claimer", ok)
}

// ---------------------------------------------------------------------------
// Test 4: vault flow — an in-test wallet mimicking vault-rust semantics
// (denominated top-up, exact-subset payment, change via /v1/swap).
// ---------------------------------------------------------------------------

type mvpWallet struct {
	t      *testing.T
	k      *Kiosk
	dev    string
	sk     ed25519.PrivateKey
	seq    uint64
	proofs []Proof
}

func mvpGreedyDenoms(v int) ([]int, error) {
	var out []int
	for i := len(Denominations) - 1; i >= 0 && v > 0; i-- {
		for v >= Denominations[i] {
			out = append(out, Denominations[i])
			v -= Denominations[i]
		}
	}
	if v != 0 {
		return nil, fmt.Errorf("cannot denominate %d", v)
	}
	return out, nil
}

func (w *mvpWallet) balance() int {
	total := 0
	for _, p := range w.proofs {
		if amt, ok := amountForKeyset(p.KeysetID); ok {
			total += amt
		}
	}
	return total
}

// mint requests one blind-signed proof per denomination (device-signed, seq No.).
func (w *mvpWallet) mint(amount int) {
	w.t.Helper()
	if err := w.k.EnsureDenominations(); err != nil { // the real kiosk does this at boot
		w.t.Fatal(err)
	}
	coins, err := mvpGreedyDenoms(amount)
	if err != nil {
		w.t.Fatalf("topup: %v", err)
	}
	for _, d := range coins {
		secret := "fupi-" + randHex16(w.t)
		N := w.k.keys[d].N
		m := mvpHashToInt([]byte(secret), N)
		r := mvpRandBlinder(w.t, N)
		blinded := b64(mvpBlind(m, r, &w.k.keys[d].PublicKey).Bytes())
		w.seq++
		sigHex := fmt.Sprintf("%x", ed25519.Sign(w.sk, []byte(DeviceSignMessage(w.dev, w.seq, d, blinded))))
		sigB64, err := w.k.SignForDevice(w.dev, w.seq, d, blinded, sigHex)
		if err != nil {
			w.t.Fatalf("blind-sign failed: %v", err)
		}
		s := mvpUnblind(modScalar(w.t, sigB64), r, &w.k.keys[d].PublicKey)
		if !mvpVerify(m, s, &w.k.keys[d].PublicKey) {
			w.t.Fatalf("mint: kiosk signature failed verification for %d", d)
		}
		w.proofs = append(w.proofs, Proof{Secret: secret, Sig: b64(s.Bytes()), KeysetID: keysetIDFor(d)})
	}
}

// pay mimics vault-rust make_payment: pick an exact subset of unlocked proofs;
// if none exists, make change via the kiosk's idempotent /v1/swap (inputs must
// be unlocked), then pick again. Locked ("p2pk") proofs carry "|lock=<pubkey
// hex>" INSIDE the blind-signed secret.
func (w *mvpWallet) pay(target int, p2pk string) (string, error) {
	w.t.Helper()
	if target <= 0 || target > w.balance() {
		return "", errors.New("payment exceeds balance")
	}
	lockHex, lockedSecretPostfix := "", ""
	if p2pk != "" {
		raw, perr := hex.DecodeString(p2pk)
		if perr != nil || len(raw) != ed25519.PublicKeySize {
			return "", fmt.Errorf("p2pk must be a 32-byte ed25519 public key in hex")
		}
		lockedSecretPostfix = "|lock=" + p2pk
		lockHex = p2pk
	}
	if subset := w.exactSubset(target, lockHex); subset != nil {
		return w.emit(subset), nil
	}
	// choose the smallest unlocked proof worth >= target and break it up
	victim := -1
	victimVal := 0
	for i, p := range w.proofs {
		val, ok := amountForKeyset(p.KeysetID)
		if !ok {
			continue
		}
		if _, locked, lerr := lockOf(p.Secret); lerr != nil || locked {
			continue
		}
		if val >= target && (victim == -1 || val < victimVal) {
			victim, victimVal = i, val
		}
	}
	if victim == -1 {
		return "", errors.New("no usable input to make change from")
	}
	victimProof := w.proofs[victim]
	outCoins, err0 := mvpGreedyDenoms(target)
	restCoins, err1 := mvpGreedyDenoms(victimVal - target)
	if err0 != nil || err1 != nil {
		return "", errors.New("change-making denominations failed")
	}
	coins := append(append([]int{}, outCoins...), restCoins...)
	// fresh secrets: payment coins locked (if p2pk), the remainder unlocked
	var outputs []SwapOut
	secrets, rs := make([]string, 0, len(coins)), make([]*big.Int, 0, len(coins))
	nPay := len(outCoins) // only the coins that pay this invoice carry the lock
	for i, d := range coins {
		sec := "fupi-" + randHex16(w.t)
		if i < nPay {
			sec += lockedSecretPostfix
		}
		N := w.k.keys[d].N
		m := mvpHashToInt([]byte(sec), N)
		r := mvpRandBlinder(w.t, N)
		blinded := b64(mvpBlind(m, r, &w.k.keys[d].PublicKey).Bytes())
		outputs = append(outputs, SwapOut{BlindedMessage: blinded, Amount: d})
		secrets = append(secrets, sec)
		rs = append(rs, r)
	}
	sigs, err := w.k.Swap([]Proof{victimProof}, outputs)
	if err != nil {
		return "", err
	}
	// drop the swapped-out input, add the fresh coins
	w.proofs = append(w.proofs[:victim], w.proofs[victim+1:]...)
	for i, d := range coins {
		s := mvpUnblind(modScalar(w.t, sigs[i]), rs[i], &w.k.keys[d].PublicKey)
		if !mvpVerify(mvpHashToInt([]byte(secrets[i]), w.k.keys[d].N), s, &w.k.keys[d].PublicKey) {
			return "", errors.New("swap output failed verification")
		}
		w.proofs = append(w.proofs, Proof{Secret: secrets[i], Sig: b64(s.Bytes()), KeysetID: keysetIDFor(d)})
	}
	subset := w.exactSubset(target, lockHex)
	if subset == nil {
		return "", errors.New("change did not produce a payable subset (kiosk swap bug)")
	}
	return w.emit(subset), nil
}

func (w *mvpWallet) emit(tokenProofs []Proof) string {
	w.t.Helper()
	// remove the emitted proofs from the wallet (they travel as bearer cash)
	idx := map[string]bool{}
	for _, p := range tokenProofs {
		idx[p.Secret] = true
	}
	var keep []Proof
	for _, p := range w.proofs {
		if !idx[p.Secret] {
			keep = append(keep, p)
		}
	}
	w.proofs = keep
	raw, err := json.Marshal(tokenProofs)
	if err != nil {
		w.t.Fatal(err)
	}
	return b64(raw)
}

// exactSubset returns one subset of proofs whose face values sum exactly to
// target (bitmask search over the wallet, like the vault's solver). Proof are
// eligible when unlocked, or locked exactly to `lock` (paying them to their
// owner). With lock == "" only unlocked proofs are eligible.
func (w *mvpWallet) exactSubset(target int, lock string) []Proof {
	w.t.Helper()
	var eligible []Proof
	for _, p := range w.proofs {
		pk, locked, lerr := lockOf(p.Secret)
		if lerr != nil {
			continue
		}
		if locked && (lock == "" || fmt.Sprintf("%x", pk) != lock) {
			continue
		}
		eligible = append(eligible, p)
	}
	n := len(eligible)
	for mask := 1; mask < (1 << n); mask++ {
		sum, cnt := 0, 0
		for i := 0; i < n; i++ {
			if mask&(1<<i) != 0 {
				v, _ := amountForKeyset(eligible[i].KeysetID)
				sum += v
				cnt++
			}
		}
		if sum == target && cnt > 0 {
			var sub []Proof
			for i := 0; i < n; i++ {
				if mask&(1<<i) != 0 {
					sub = append(sub, eligible[i])
				}
			}
			return sub
		}
	}
	return nil
}

func mvpDecodeToken(t *testing.T, tok string) []Proof {
	t.Helper()
	raw, err := unb64(tok)
	if err != nil {
		t.Fatalf("token decode: %v", err)
	}
	var proofs []Proof
	if json.Unmarshal(raw, &proofs) != nil {
		t.Fatalf("token is not a proof list")
	}
	return proofs
}

func mvpTokenValue(proofs []Proof) int {
	total := 0
	for _, p := range proofs {
		if v, ok := amountForKeyset(p.KeysetID); ok {
			total += v
		}
	}
	return total
}

func allLockedTo(proofs []Proof, lockHex string) bool {
	for _, p := range proofs {
		pk, locked, err := lockOf(p.Secret)
		if err != nil || !locked || fmt.Sprintf("%x", pk) != lockHex {
			return false
		}
	}
	return true
}

// mvpVerifyOffline ports Vault.verify_offline: every proof must carry a valid
// mint signature against its own pinned keyset (n/e fetched from the kiosk) and
// any lock inside the secret must be well-formed.
func mvpVerifyOffline(t *testing.T, proofs []Proof, pinned []KeysetInfo) bool {
	t.Helper()
	byID := map[string]KeysetInfo{}
	for _, ks := range pinned {
		byID[ks.KeysetID] = ks
	}
	for _, p := range proofs {
		ks, ok := byID[p.KeysetID]
		if !ok {
			return false // never trust a token's own n/e — keyset must be pinned
		}
		pub := rsa.PublicKey{N: new(big.Int).SetBytes(mustUnb64(ks.N)), E: ks.E}
		if !mvpVerify(mvpHashToInt([]byte(p.Secret), pub.N), modScalar(t, p.Sig), &pub) {
			return false
		}
		if _, locked, err := lockOf(p.Secret); err != nil || (locked && len(p.Secret) > 256) {
			return false
		}
	}
	return true
}

func TestMvp04VaultFlow(t *testing.T) {
	defer mvpReport(t)
	k, err := NewKiosk(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	k.CreditReserve(10)
	pkDev, sk, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := k.AllocateDevice(fmt.Sprintf("%x", pkDev), 10, "alloc-mvp"); err != nil {
		t.Fatal(err)
	}
	w := &mvpWallet{t: t, k: k, dev: fmt.Sprintf("%x", pkDev), sk: sk}

	w.mint(10)
	mvpCheck(t, "vault balance after topup", w.balance() == 10)

	lockPub, _, _ := ed25519.GenerateKey(rand.Reader)
	lockHex := fmt.Sprintf("%x", lockPub)
	tok, err := w.pay(3, lockHex)
	if err != nil {
		t.Fatalf("pay 3: %v", err)
	}
	proofs := mvpDecodeToken(t, tok)
	mvpCheck(t, "token decodes to exactly value 3", mvpTokenValue(proofs) == 3)
	mvpCheck(t, "p2pk lock carried inside every proof secret", len(proofs) > 0 && allLockedTo(proofs, lockHex))
	mvpCheck(t, "offline verify passes", mvpVerifyOffline(t, proofs, k.Keysets()))
	mvpCheck(t, "vault balance after spend", w.balance() == 7)

	_, err = w.pay(100, "")
	mvpCheck(t, "spend blocked when over balance", err != nil)
}
