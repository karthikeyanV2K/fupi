package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func settleN(t *testing.T, k *Kiosk, merchant string, amount int, secret string) {
	t.Helper()
	p := blindFor(t, k, amount, secret, anonSign(k, amount))
	if ok, msg := k.SettleFor(p, merchant); !ok {
		t.Fatalf("settle %s: %s", secret, msg)
	}
}

func balanceOf(t *testing.T, k *Kiosk, name string) MerchantBalance {
	t.Helper()
	_, bals := k.SettlementReport(0, 0, name)
	if len(bals) != 1 {
		t.Fatalf("want one balance for %q, got %+v", name, bals)
	}
	return bals[0]
}

func TestSettlementLogGroupsByMerchantAndSanitisesLabels(t *testing.T) {
	k := newDenomKiosk(t)
	k.allowAnon = true
	k.CreditReserve(1000)
	settleN(t, k, "shop-1", 50, "w4-a")
	settleN(t, k, "shop-1", 20, "w4-b")
	settleN(t, k, "shop-2", 5, "w4-c")
	settleN(t, k, "", 2, "w4-d")
	settleN(t, k, "bad label; drop table", 1, "w4-e") // junk label never reaches the log

	if b := balanceOf(t, k, "shop-1"); b.Settled != 70 || b.Owed != 70 || b.Count != 2 {
		t.Fatalf("shop-1: %+v", b)
	}
	if b := balanceOf(t, k, unlabeled); b.Settled != 3 || b.Count != 2 {
		t.Fatalf("unlabeled: %+v", b)
	}
	entries, _ := k.SettlementReport(2, 0, "")
	if len(entries) != 3 || entries[0].Seq != 3 {
		t.Fatalf("since filter broke: %+v", entries)
	}
	for _, e := range entries {
		if len(e.Proof) != 16 || strings.Contains(e.Proof, "w4-") {
			t.Fatalf("proof tag leaks the secret or is malformed: %q", e.Proof)
		}
	}
	// A rejected double-spend is not logged.
	dup := blindFor(t, k, 5, "w4-c", anonSign(k, 5))
	if ok, _ := k.SettleFor(dup, "shop-2"); ok {
		t.Fatal("settled a reused secret twice")
	}
	if rc := k.Reconcile(); rc.SettledTotal != 78 || rc.OwedTotal != 78 || !rc.FullyBacked {
		t.Fatalf("reconcile: %+v", rc)
	}
}

func TestPayoutLowersOwedAndReserveAndIsReplaySafe(t *testing.T) {
	k := newDenomKiosk(t)
	k.allowAnon = true
	k.CreditReserve(500)
	settleN(t, k, "shop-1", 100, "w4-p1")
	settleN(t, k, "shop-1", 50, "w4-p2")

	if _, err := k.RecordPayout("shop-1", 200, "UTR-A"); err != ErrOverPayout {
		t.Fatalf("overpay: got %v", err)
	}
	if _, err := k.RecordPayout("nobody", 1, "UTR-B"); err != ErrOverPayout {
		t.Fatalf("unknown merchant owed nothing: got %v", err)
	}
	for _, c := range []struct {
		m, ref string
		amt    int
		want   error
	}{{"", "r", 1, ErrBadMerchant}, {"x y", "r", 1, ErrBadMerchant}, {"shop-1", "", 1, ErrBadRef}, {"shop-1", "r", 0, ErrBadAmount}} {
		if _, err := k.RecordPayout(c.m, c.amt, c.ref); err != c.want {
			t.Fatalf("%+v: got %v", c, err)
		}
	}
	b, err := k.RecordPayout("shop-1", 120, "UTR-1")
	if err != nil || b.Owed != 30 || b.Paid != 120 {
		t.Fatalf("payout: %+v %v", b, err)
	}
	if _, err := k.RecordPayout("shop-1", 10, "UTR-1"); err != ErrDupPayout {
		t.Fatalf("replayed payout ref: got %v", err)
	}
	rc := k.Reconcile()
	if rc.Reserve != 380 || rc.PaidTotal != 120 || rc.OwedTotal != 30 || !rc.FullyBacked || !rc.LedgerConsistent {
		t.Fatalf("reconcile after payout: %+v", rc)
	}
}

func TestOwedMoneyCountsAgainstIssuance(t *testing.T) {
	k := newDenomKiosk(t)
	k.allowAnon = true
	k.CreditReserve(60)
	settleN(t, k, "shop-1", 50, "w4-b1") // issued back to 0, but 50 is now owed to shop-1
	// Only 10 of the 60 is free: a 20 would leave issued(20)+owed(50) > reserve(60).
	if _, err := k.BlindSign("Ag", 20); err == nil {
		t.Fatal("kiosk issued money that is already promised to a merchant")
	}
	if _, err := k.BlindSign("Ag", 10); err != nil {
		t.Fatalf("10 should still fit: %v", err)
	}
	// Paying the merchant out frees nothing (the bank balance fell too) but keeps it consistent.
	if _, err := k.RecordPayout("shop-1", 50, "UTR-O"); err != nil {
		t.Fatal(err)
	}
	if rc := k.Reconcile(); !rc.FullyBacked || !rc.LedgerConsistent || rc.Reserve != 10 {
		t.Fatalf("%+v", rc)
	}
}

func TestSettlementsAndPayoutsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	k, err := NewKiosk(path)
	if err != nil {
		t.Fatal(err)
	}
	for d, key := range cachedDenomKeys(t) {
		k.keys[d] = key
	}
	k.allowAnon = true
	k.CreditReserve(300)
	settleN(t, k, "shop-9", 100, "w4-r1")
	if _, err := k.RecordPayout("shop-9", 40, "UTR-R"); err != nil {
		t.Fatal(err)
	}
	k2, err := NewKiosk(path)
	if err != nil {
		t.Fatal(err)
	}
	if b := balanceOf(t, k2, "shop-9"); b.Settled != 100 || b.Paid != 40 || b.Owed != 60 {
		t.Fatalf("after restart: %+v", b)
	}
	if _, err := k2.RecordPayout("shop-9", 1, "UTR-R"); err != ErrDupPayout {
		t.Fatalf("payout ref replay after restart: %v", err)
	}
	if rc := k2.Reconcile(); rc.Reserve != 260 || !rc.LedgerConsistent {
		t.Fatalf("reconcile after restart: %+v", rc)
	}
}

func TestSettlementEndpointsNeedOperatorAuth(t *testing.T) {
	k := newDenomKiosk(t)
	k.allowAnon = true
	k.CreditReserve(200)
	settleN(t, k, "shop-1", 50, "w4-h1")
	mux := SetupMux(k, false, "")

	get := func(uri, secret string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", uri, nil)
		if secret != "" {
			req.Header.Set("X-Fupi-Signature", hmacHex([]byte(secret), []byte(uri)))
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	if rr := get("/v1/settlements", "s"); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled: %d", rr.Code)
	}
	k.SetCreditSecret("s")
	if rr := get("/v1/settlements", ""); rr.Code != 401 {
		t.Fatalf("unsigned: %d", rr.Code)
	}
	if rr := get("/v1/settlements", "wrong"); rr.Code != 401 {
		t.Fatalf("wrong secret: %d", rr.Code)
	}
	// The signature covers the query: a signed ?since=0 cannot be replayed as ?merchant=...
	req := httptest.NewRequest("GET", "/v1/settlements?merchant=shop-1", nil)
	req.Header.Set("X-Fupi-Signature", hmacHex([]byte("s"), []byte("/v1/settlements?since=0")))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Fatalf("query tampering: %d", rr.Code)
	}
	rr = get("/v1/settlements?since=0", "s")
	var out struct {
		Entries   []Settlement      `json:"entries"`
		Merchants []MerchantBalance `json:"merchants"`
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil || len(out.Entries) != 1 || out.Merchants[0].Owed != 50 {
		t.Fatalf("report: %d %s", rr.Code, rr.Body.String())
	}

	post := func(secret, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/v1/payout", strings.NewReader(body))
		if secret != "" {
			req.Header.Set("X-Fupi-Signature", hmacHex([]byte(secret), []byte(body)))
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	ok := `{"merchant":"shop-1","amount":30,"ref":"UTR-H"}`
	if rr := post("", ok); rr.Code != 401 {
		t.Fatalf("unsigned payout: %d", rr.Code)
	}
	if rr := post("s", `{"merchant":"shop-1","amount":99,"ref":"UTR-X"}`); rr.Code != 402 {
		t.Fatalf("overpay: %d", rr.Code)
	}
	if rr := post("s", ok); rr.Code != 200 {
		t.Fatalf("payout: %d %s", rr.Code, rr.Body.String())
	}
	if rr := post("s", ok); rr.Code != 409 {
		t.Fatalf("replay: %d", rr.Code)
	}
}

func TestSettleHeaderSetsMerchantLabel(t *testing.T) {
	k := newDenomKiosk(t)
	k.allowAnon = true
	k.CreditReserve(100)
	p := blindFor(t, k, 20, "w4-hdr", anonSign(k, 20))
	body, _ := json.Marshal(p)
	req := httptest.NewRequest("POST", "/v1/settle", strings.NewReader(string(body)))
	req.Header.Set("X-Fupi-Merchant", "cafe-7")
	rr := httptest.NewRecorder()
	SetupMux(k, false, "").ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("settle: %d %s", rr.Code, rr.Body.String())
	}
	if b := balanceOf(t, k, "cafe-7"); b.Settled != 20 {
		t.Fatalf("%+v", b)
	}
}
