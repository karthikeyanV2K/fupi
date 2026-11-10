// Package main: POST /v1/webhook — the kiosk's OWN gateway-callback endpoint.
// Point Razorpay / Cashfree / Stripe / your bank's corp API webhook directly
// at this kiosk. Signature verification mirrors bank_rail.py's WebhookBank:
// hex(HMAC-SHA256(secret, RAW body)) in a `X-Razorpay-Signature` OR
// `X-Fupi-Signature` header, constant-time compared; a replayed ref (order id)
// is answered 409 WITHOUT crediting again (gateways retry deliveries).

// fupi/kiosk-go: POST /v1/webhook — the kiosk's OWN gateway-callback endpoint.
// Point Razorpay / Cashfree / Stripe / your bank's corp API webhook directly
// at this kiosk. Signature verification mirrors the retired WebhookBank:
// hex(HMAC-SHA256(secret, RAW body)) in a `X-Razorpay-Signature` OR
// `X-Fupi-Signature` header, constant-time compared; a replayed ref (order id)
// is answered 409 WITHOUT crediting again (gateways retry deliveries).
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const webhookMaxBody = 65536 // same cap as the retired Python server

func (k *Kiosk) webhookSigValid(raw []byte, sigHex string) bool {
	sigHex = strings.TrimSpace(sigHex)
	if sigHex == "" {
		return false
	}
	got, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	k.mu.Lock()
	secret := k.creditSecret
	k.mu.Unlock()
	if len(secret) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(raw)
	return hmac.Equal(mac.Sum(nil), got)
}

// registerWebhook mounts POST /v1/webhook on the kiosk mux.
func (k *Kiosk) registerWebhook(mux *http.ServeMux) {
	mux.HandleFunc("/v1/webhook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if !k.CreditEnabled() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "webhook disabled: set -credit-secret or FUPI_CREDIT_SECRET"})
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, webhookMaxBody))
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request body"})
			return
		}
		sig := r.Header.Get("X-Razorpay-Signature")
		if sig == "" {
			sig = r.Header.Get("X-Fupi-Signature")
		}
		if !k.webhookSigValid(raw, sig) {
			writeJSON(w, 401, map[string]string{"error": "bad or missing signature"})
			return
		}
		reserve, derr := k.webhookProcess(raw, "gateway")
		var body webhookBody
		_ = json.Unmarshal(raw, &body)
		switch {
		case derr == nil:
			writeJSON(w, 200, map[string]float64{"reserve": moneyMinor(reserve)})
		case derr == ErrBadRailInput:
			writeJSON(w, 400, map[string]string{
				"error": `amount must be minor units > 0 and order_id/ref required`})
		case errors.Is(derr, ErrDupRef):
			writeJSON(w, 409, map[string]string{"error": derr.Error()}) // gateway retry: already credited
		case errors.Is(derr, ErrBadRef), errors.Is(derr, ErrBadAmount):
			writeJSON(w, 400, map[string]string{"error": derr.Error()})
		default:
			writeJSON(w, 502, map[string]string{"error": "credit failed on this side; retry delivery"})
		}
	})
}
