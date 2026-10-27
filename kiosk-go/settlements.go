package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"
)

// W4: settlement log + payout ledger. The kiosk records every accepted settlement (who
// presented it, how much) so the operator can pay merchants from the bank, and records each
// payout so "owed" falls and the reserve falls with the real bank balance.
//
// The merchant label comes from an unauthenticated header: it says who to PAY, not who owns
// the money (a bearer proof is cash). The operator confirms the payee out of band.

type Settlement struct {
	Seq      int    `json:"seq"`
	At       string `json:"at"`
	Merchant string `json:"merchant"`
	Amount   int    `json:"amount"`
	KeysetID string `json:"keyset_id"`
	Proof    string `json:"proof"` // first 16 hex of SHA-256(secret): traceable, not spendable
}

type Payout struct {
	Ref      string `json:"ref"`
	Merchant string `json:"merchant"`
	Amount   int    `json:"amount"`
	At       string `json:"at"`
}

type MerchantBalance struct {
	Merchant string `json:"merchant"`
	Settled  int    `json:"settled"`
	Paid     int    `json:"paid"`
	Owed     int    `json:"owed"`
	Count    int    `json:"count"`
}

var (
	ErrBadMerchant = errors.New("merchant required (1-64 chars of A-Z a-z 0-9 . _ @ -)")
	ErrOverPayout  = errors.New("payout exceeds what is owed to this merchant")
	ErrDupPayout   = errors.New("duplicate payout reference")
)

const unlabeled = "(unlabeled)"

// cleanMerchant returns a safe label ("" -> unlabeled). ok=false for junk.
func cleanMerchant(s string) (string, bool) {
	if s == "" {
		return unlabeled, true
	}
	if len(s) > 64 {
		return "", false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '@' || c == '-') {
			return "", false
		}
	}
	return s, true
}

func proofTag(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:8])
}

// balancesLocked sums the log per merchant. Caller holds k.mu.
func (k *Kiosk) balancesLocked() []MerchantBalance {
	m := map[string]*MerchantBalance{}
	get := func(name string) *MerchantBalance {
		if m[name] == nil {
			m[name] = &MerchantBalance{Merchant: name}
		}
		return m[name]
	}
	for _, s := range k.settlements {
		b := get(s.Merchant)
		b.Settled += s.Amount
		b.Count++
	}
	for _, p := range k.payouts {
		get(p.Merchant).Paid += p.Amount
	}
	out := make([]MerchantBalance, 0, len(m))
	for _, b := range m {
		b.Owed = b.Settled - b.Paid
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Merchant < out[j].Merchant })
	return out
}

func (k *Kiosk) owedTotalLocked() int {
	t := 0
	for _, s := range k.settlements {
		t += s.Amount
	}
	for _, p := range k.payouts {
		t -= p.Amount
	}
	return t
}

// SettlementReport returns log entries with Seq > since (at most limit) and every
// merchant's running balance.
func (k *Kiosk) SettlementReport(since, limit int, merchant string) ([]Settlement, []MerchantBalance) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var entries []Settlement
	for _, s := range k.settlements {
		if s.Seq > since && (merchant == "" || s.Merchant == merchant) {
			entries = append(entries, s)
			if len(entries) == limit {
				break
			}
		}
	}
	bals := k.balancesLocked()
	if merchant != "" {
		var f []MerchantBalance
		for _, b := range bals {
			if b.Merchant == merchant {
				f = append(f, b)
			}
		}
		bals = f
	}
	return entries, bals
}

// RecordPayout books money the operator has paid out of the bank to a merchant. It lowers
// both what the merchant is owed and the reserve (the bank balance went down by the same
// amount). Unique ref (bank UTR) makes it replay-safe.
func (k *Kiosk) RecordPayout(merchant string, amount int, ref string) (MerchantBalance, error) {
	name, ok := cleanMerchant(merchant)
	if !ok || merchant == "" {
		return MerchantBalance{}, ErrBadMerchant
	}
	if ref == "" || len(ref) > 128 {
		return MerchantBalance{}, ErrBadRef
	}
	if amount <= 0 {
		return MerchantBalance{}, ErrBadAmount
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, dup := k.payoutRefs[ref]; dup {
		return MerchantBalance{}, ErrDupPayout
	}
	var cur MerchantBalance
	for _, b := range k.balancesLocked() {
		if b.Merchant == name {
			cur = b
		}
	}
	if amount > cur.Owed {
		return cur, ErrOverPayout
	}
	oldReserve := k.reserve
	k.payouts = append(k.payouts, Payout{Ref: ref, Merchant: name, Amount: amount, At: time.Now().UTC().Format(time.RFC3339)})
	k.payoutRefs[ref] = struct{}{}
	k.reserve -= float64(amount)
	if err := k.saveState(); err != nil {
		k.payouts = k.payouts[:len(k.payouts)-1]
		delete(k.payoutRefs, ref)
		k.reserve = oldReserve
		return cur, fmt.Errorf("could not persist payout: %w", err)
	}
	log.Printf("[kiosk] payout ref=%s merchant=%s -%d", ref, name, amount)
	cur.Paid += amount
	cur.Owed -= amount
	return cur, nil
}
