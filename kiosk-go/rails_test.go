// Package main — tests for the native money-ingest rails (rails.go/webhook.go):
// CSV import idempotency and the gateway webhook endpoint (auth/replay).
package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCsvImportIsIdempotentAndFiltered(t *testing.T) {
	k, err := NewKiosk(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	csvPath := filepath.Join(t.TempDir(), "sbi.csv")
	body := "Date,Narration,ChqNo,Withdrawal Amt.,Deposit Amt.,Closing Balance\n" +
		"01-01-2026,FUPI-ABC123 NEFT,,-,500.00,500.00\n" +
		"02-01-2026,SALARY PAYROLL,,,-,42000.00\n" + // no FUPI suffix match
		"03-01-2026,FUPI-XYZ789 IMPS,,200.00,\"1,000.00\",\"\u20b91,000.00\"\n"
	if err := os.WriteFile(csvPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	credited, rows, err := k.runCsvImport(csvPath, "FUPI")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if rows != 2 || credited != 1500.0 {
		t.Fatalf("first import credited %.2f over %d rows (want 1500.00 / 2)", credited, rows)
	}
	if k.ReserveForTest() != 1500.0 {
		t.Fatalf("reserve = %.2f, want 1500.00", k.ReserveForTest())
	}
	// Same file AGAIN: row-hash references must make it a no-op.
	credited2, rows2, err := k.runCsvImport(csvPath, "FUPI")
	if err != nil {
		t.Fatal(err)
	}
	if rows2 != 0 || credited2 != 0 {
		t.Fatalf("re-import double-credited: +%.2f over %d rows (want 0 / 0)", credited2, rows2)
	}
	if k.ReserveForTest() != 1500.0 {
		t.Fatalf("reserve after re-import = %.2f, want unchanged 1500.00", k.ReserveForTest())
	}
}

func TestWebhookEndpointAuthReplayAndCredit(t *testing.T) {
	k, err := NewKiosk(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	k.SetCreditSecret("wh-test-secret")
	mux := SetupMux(k, false, "")
	ts := httptest.NewServer(mux)
	defer ts.Close()

	post := func(sig string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/v1/webhook", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if sig != "" {
			req.Header.Set("X-Razorpay-Signature", sig)
		}
		w := httptest.NewRecorder()
		ts.Config.Handler.ServeHTTP(w, req)
		return w
	}

	raw := []byte(`{"amount":25000,"order_id":"order_GH99x"}`)
	sig := hmacHex([]byte("wh-test-secret"), raw)

	// No signature / wrong signature: 401, nothing credited.
	if w := post("", raw); w.Code != 401 {
		t.Fatalf("webhook without signature: code %d, want 401", w.Code)
	}
	if w := post(hmacHex([]byte("intruder"), raw), raw); w.Code != 401 {
		t.Fatalf("webhook with wrong signature: code %d, want 401", w.Code)
	}
	if k.ReserveForTest() != 0 {
		t.Fatalf("reserve moved on rejected webhooks: %.2f", k.ReserveForTest())
	}
	// Valid signature: 200, reserve rises by 250.00 paise→major conversion.
	if w := post(sig, raw); w.Code != 200 {
		t.Fatalf("good webhook: code %d (%s)", w.Code, w.Body.String())
	}
	if k.ReserveForTest() != 250.0 {
		t.Fatalf("reserve = %.2f, want 250.00", k.ReserveForTest())
	}
	// Gateway retry with the SAME order id: 409, reserve unchanged.
	if w := post(sig, raw); w.Code != 409 {
		t.Fatalf("replayed webhook: code %d, want 409", w.Code)
	}
	if k.ReserveForTest() != 250.0 {
		t.Fatalf("reserve after replay = %.2f, want unchanged 250.00", k.ReserveForTest())
	}
}

// ReserveForTest is a small read helper for tests.
func (k *Kiosk) ReserveForTest() float64 {
	return k.Reconcile().Reserve
}
