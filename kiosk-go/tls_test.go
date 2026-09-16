package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestSelfSignedTLSServer(t *testing.T) {
	k, err := NewKiosk("")
	if err != nil {
		t.Fatal(err)
	}
	k.CreditReserve(50)

	tlsCert, certPEM, _, fp, err := generateSelfSignedCert([]string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatalf("failed to generate TLS cert: %v", err)
	}
	if fp == "" {
		t.Fatal("empty TLS fingerprint")
	}

	mux := SetupMux(k, true, fp)

	// Pick free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	tlsListener := tls.NewListener(listener, tlsConfig)

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(tlsListener)
	}()
	defer server.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	baseURL := fmt.Sprintf("https://127.0.0.1:%d", port)

	// Setup client with custom root CA pool trusting certPEM
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to append self-signed cert to client cert pool")
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
		Timeout: 5 * time.Second,
	}

	// 1. Check GET /v1/info
	resp, err := client.Get(baseURL + "/v1/info")
	if err != nil {
		t.Fatalf("failed GET /v1/info: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200 from /v1/info, got %d", resp.StatusCode)
	}
	var info AtmInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatalf("failed to decode /v1/info: %v", err)
	}
	if !info.TLSEnabled {
		t.Fatal("expected TLSEnabled to be true")
	}
	if info.TLSFingerprint != fp {
		t.Fatalf("fingerprint mismatch: got %s want %s", info.TLSFingerprint, fp)
	}

	// 2. Check GET /v1/keyset
	resp2, err := client.Get(baseURL + "/v1/keyset")
	if err != nil {
		t.Fatalf("failed GET /v1/keyset: %v", err)
	}
	defer resp2.Body.Close()
	var ks Keyset
	if err := json.NewDecoder(resp2.Body).Decode(&ks); err != nil {
		t.Fatalf("failed to decode keyset: %v", err)
	}
	if ks.KeysetID != "go-mvp-00" || ks.E != 65537 {
		t.Fatalf("invalid keyset returned: %+v", ks)
	}

	// 3. Perform Blind Sign over HTTPS
	secret := []byte("tls-test-secret-001")
	m := hashToScalar(secret, k.key.N)
	r := big.NewInt(5)
	e := big.NewInt(int64(k.key.PublicKey.E))
	mB := new(big.Int).Mul(m, new(big.Int).Exp(r, e, k.key.N))
	mB.Mod(mB, k.key.N)

	reqBody, _ := json.Marshal(map[string]any{
		"blinded_message": b64(mB.Bytes()),
		"amount":          1,
	})
	resp3, err := client.Post(baseURL+"/v1/blind-sign", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed POST /v1/blind-sign: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != 200 {
		t.Fatalf("expected 200 from /v1/blind-sign, got %d", resp3.StatusCode)
	}
	var signResp struct {
		BlindSignature string `json:"blind_signature"`
	}
	if err := json.NewDecoder(resp3.Body).Decode(&signResp); err != nil {
		t.Fatalf("failed to decode sign response: %v", err)
	}

	// Unblind
	sB := new(big.Int).SetBytes(mustUnb64(signResp.BlindSignature))
	rInv := new(big.Int).ModInverse(r, k.key.N)
	sig := new(big.Int).Mod(new(big.Int).Mul(sB, rInv), k.key.N)

	// Verify locally
	chk := new(big.Int).Exp(sig, e, k.key.N)
	if chk.Cmp(m) != 0 {
		t.Fatalf("local unblind verification failed")
	}

	// 4. Settle over HTTPS
	proof := Proof{
		Secret: string(secret),
		Sig:    b64(sig.Bytes()),
	}
	proofBytes, _ := json.Marshal(proof)
	resp4, err := client.Post(baseURL+"/v1/settle", "application/json", bytes.NewReader(proofBytes))
	if err != nil {
		t.Fatalf("failed POST /v1/settle: %v", err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != 200 {
		t.Fatalf("expected 200 from settle, got %d", resp4.StatusCode)
	}

	// 5. Replay over HTTPS should fail with 409
	resp5, err := client.Post(baseURL+"/v1/settle", "application/json", bytes.NewReader(proofBytes))
	if err != nil {
		t.Fatalf("failed POST /v1/settle replay: %v", err)
	}
	defer resp5.Body.Close()
	if resp5.StatusCode != 409 {
		t.Fatalf("expected 409 conflict for double-spend, got %d", resp5.StatusCode)
	}
}
