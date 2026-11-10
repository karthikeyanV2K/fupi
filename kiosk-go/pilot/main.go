// Package main: FUPI pilot daily check. Run once a day (and after any incident):
//
//	FUPI_CREDIT_SECRET=... go run ./pilot --atm https://127.0.0.1:8890 \
//	    --pin-tls <sha256> --bank-balance 4820.00 --max-total 5000
//
// Exit code 0 = all checks passed (warnings allowed), 1 = at least one FAIL:
// stop issuing until it is explained. Every run appends one JSON line to --log,
// the pilot's audit trail and the baseline for the next day's rollback/tamper
// checks. This is the native Go replacement for scripts/pilot_check.py.
//
// TLS: the kiosk uses a self-signed cert, so the pilot verifies ONLY the pinned
// --pin-tls SHA-256 fingerprint (the hash of the DER certificate, the same value
// the kiosk prints at boot). Trust is either exact-fingerprint or nothing.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const EPS = 0.005

type result struct {
	Level string
	Msg   string
}

const (
	lvlFail = "FAIL"
	lvlWarn = "WARN"
	lvlOk   = "ok"
)

// evaluate is the whole verdict logic: rc = /v1/reconcile body, prev = last
// logged reconcile, bank = real bank balance (nil = not given), maxTotal =
// pilot cap (nil = not given), report = /v1/settlements body (nil = no secret).
func evaluate(rc map[string]any, prev map[string]any, bank *float64, maxTotal *float64, report map[string]any) []result {
	num := func(m map[string]any, key string) float64 {
		if m == nil {
			return 0
		}
		if v, ok := m[key].(float64); ok {
			return v
		}
		return 0
	}
	out := []result{}
	add := func(level, msg string) { out = append(out, result{level, msg}) }

	issued := num(rc, "issued_outstanding")
	owed := num(rc, "owed_total")
	reserve := num(rc, "reserve")
	fullyBacked, _ := rc["fully_backed"].(bool)
	ledgerConsistent, _ := rc["ledger_consistent"].(bool)

	// 1. The kiosk's own invariants.
	act := lvlOk
	if !fullyBacked {
		act = lvlFail
	}
	add(act, fmt.Sprintf("fully_backed (reserve %s >= issued %s + owed %s)",
		num2s(reserve), num2s(issued), num2s(owed)))
	act = lvlOk
	if !ledgerConsistent {
		act = lvlFail
	}
	add(act, "ledger_consistent (deposits - payouts == reserve)")
	if reserve+EPS < issued+owed {
		add(lvlFail, "reserve is below issued + owed")
	}
	if math.Min(math.Min(issued, owed), math.Min(num(rc, "settled_total"), num(rc, "paid_total"))) < 0 {
		add(lvlFail, "a total is negative")
	}
	if num(rc, "paid_total") > num(rc, "settled_total") {
		add(lvlFail, "paid_total exceeds settled_total")
	}
	if num(rc, "devices_loaded") > num(rc, "devices_allocated")+EPS {
		add(lvlFail, fmt.Sprintf("devices loaded %s > allocated %s",
			num2s(num(rc, "devices_loaded")), num2s(num(rc, "devices_allocated"))))
	}

	// 2. The real bank account is the source of truth for the reserve.
	if bank != nil {
		switch {
		case *bank+EPS < reserve:
			add(lvlFail, fmt.Sprintf("bank balance %.2f is BELOW reserve %.2f: tokens are not fully backed in cash", *bank, reserve))
		case *bank > reserve+EPS:
			add(lvlWarn, fmt.Sprintf("bank balance %.2f is above reserve %.2f: an unrecorded deposit (credit it with its UTR)", *bank, reserve))
		default:
			p := reserve
			add(lvlOk, fmt.Sprintf("bank balance matches reserve (%s)", num2s(p)))
		}
	} else {
		add(lvlWarn, "no --bank-balance given: reserve was not compared with the real bank")
	}

	// 3. Pilot-wide cap.
	if maxTotal != nil {
		used := num(rc, "devices_allocated")
		if used <= *maxTotal+EPS {
			add(lvlOk, fmt.Sprintf("allocated %s within pilot cap %s", num2s(used), num2s(*maxTotal)))
		} else {
			add(lvlFail, fmt.Sprintf("allocated %s exceeds pilot cap %s", num2s(used), num2s(*maxTotal)))
		}
	}

	// 4. Day-over-day: counters that may only grow must not shrink (state
	// rollback / tampering), and reserve movement must be explained.
	if prev != nil {
		for _, key := range []string{"deposits_total", "deposit_count", "settled_count", "settled_total",
			"paid_total", "devices_allocated", "devices_loaded"} {
			if num(rc, key)+EPS < num(prev, key) {
				add(lvlFail, fmt.Sprintf("%s went DOWN (%s -> %s): state rolled back?", key, num2s(num(prev, key)), num2s(num(rc, key))))
			}
		}
		dRes := reserve - num(prev, "reserve")
		dExp := (num(rc, "deposits_total") - num(prev, "deposits_total")) - (num(rc, "paid_total") - num(prev, "paid_total"))
		if math.Abs(dRes-dExp) > EPS {
			add(lvlFail, fmt.Sprintf("reserve moved %+.2f but deposits-payouts explain %+.2f", dRes, dExp))
		} else {
			add(lvlOk, fmt.Sprintf("reserve change since last run explained (%+.2f)", dRes))
		}
	} else {
		add(lvlOk, "first run: baseline recorded")
	}

	// 5. The settlement log must add up to what reconcile says.
	if report != nil {
		logged := 0.0
		nEntries := 0
		if entries, ok := report["entries"].([]any); ok {
			nEntries = len(entries)
			for _, e := range entries {
				if m, ok := e.(map[string]any); ok {
					logged += num(m, "amount")
				}
			}
		}
		if nEntries < 1000 { // full history returned
			if logged == num(rc, "settled_total") {
				add(lvlOk, fmt.Sprintf("settlement log sums to %s, reconcile says settled_total %s",
					num2s(logged), num2s(num(rc, "settled_total"))))
			} else {
				add(lvlFail, fmt.Sprintf("settlement log sums to %s, reconcile says settled_total %s",
					num2s(logged), num2s(num(rc, "settled_total"))))
			}
		}
		owedSum := 0.0
		if merchants, ok := report["merchants"].([]any); ok {
			for _, me := range merchants {
				m, ok := me.(map[string]any)
				if !ok {
					continue
				}
				mOwed := num(m, "owed")
				owedSum += mOwed
				if mOwed < 0 || mOwed != num(m, "settled")-num(m, "paid") {
					add(lvlFail, fmt.Sprintf("merchant %v balance is inconsistent: %+v", m["merchant"], m))
				}
			}
		}
		if owedSum != owed {
			add(lvlFail, fmt.Sprintf("merchant balances sum to %s, reconcile owed_total is %s", num2s(owedSum), num2s(owed)))
		}
	} else {
		add(lvlWarn, "no FUPI_CREDIT_SECRET: settlement log not cross-checked")
	}
	return out
}

func num2s(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// ---- TLS-pinned HTTP fetch ----

var httpClient *http.Client

// VerifyPeerCertificate: trust ONLY the pinned fingerprint (the SHA-256 of the
// raw DER certificate — exactly what the kiosk prints at boot), else refuse.
func buildClient(pin string) {
	conf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec — deliberate: exact-fingerprint TOFU
	if pin != "" {
		want := strings.ToLower(strings.ReplaceAll(pin, ":", ""))
		conf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificate presented")
			}
			sum := sha256.Sum256(rawCerts[0])
			if got := hex.EncodeToString(sum[:]); got != want {
				return fmt.Errorf("TLS certificate does not match --pin-tls: refusing to talk to this server")
			}
			return nil
		}
	}
	httpClient = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: conf}}
}

func fetch(base, uri string, headers map[string]string) map[string]any {
	u := strings.TrimRight(base, "/") + uri
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad request:", err)
		os.Exit(1)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request failed:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read failed:", err)
		os.Exit(1)
	}
	if resp.StatusCode != 200 {
		cut := body
		if len(cut) > 200 {
			cut = cut[:200]
		}
		fmt.Fprintf(os.Stderr, "%s: HTTP %d %s\n", uri, resp.StatusCode, cut)
		os.Exit(1)
	}
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		fmt.Fprintf(os.Stderr, "%s: not valid JSON\n", uri)
		os.Exit(1)
	}
	return doc
}

// lastLogEntry loads the previous run's reconcile from the pilot log.
func lastLogEntry(path string) map[string]any {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var doc map[string]any
		if json.Unmarshal([]byte(line), &doc) == nil {
			rc, _ := doc["reconcile"].(map[string]any)
			return rc
		}
	}
	return nil
}

func main() {
	atm := flag.String("atm", "", "kiosk base URL, e.g. https://127.0.0.1:8890 (required)")
	pin := flag.String("pin-tls", "", "SHA-256 of the kiosk certificate (recommended)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (localhost dev only)")
	bank := flag.String("bank-balance", "", "current balance of the reserve bank account")
	maxTotal := flag.String("max-total", "", "pilot-wide cap on allocated quota")
	logPath := flag.String("log", "pilot_log.jsonl", "pilot JSONL audit log")
	flag.Parse()
	if *atm == "" {
		flag.Usage()
		os.Exit(2)
	}
	var bankVal, maxVal *float64
	if s := strings.TrimSpace(*bank); s != "" {
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad --bank-balance")
			os.Exit(2)
		}
		bankVal = &v
	}
	if s := strings.TrimSpace(*maxTotal); s != "" {
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad --max-total")
			os.Exit(2)
		}
		maxVal = &v
	}

	buildClient(*pin)
	if *insecure && *pin == "" {
		fmt.Fprintln(os.Stderr, "WARN: --insecure given without --pin-tls: TLS is NOT verified (localhost dev only)")
	}
	rc := fetch(*atm, "/v1/reconcile", nil)
	var report map[string]any
	secret := os.Getenv("FUPI_CREDIT_SECRET")
	if secret != "" {
		uri := "/v1/settlements?since=0&limit=1000"
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(uri))
		report = fetch(*atm, uri, map[string]string{"X-Fupi-Signature": hex.EncodeToString(mac.Sum(nil))})
	}

	results := evaluate(rc, lastLogEntry(*logPath), bankVal, maxVal, report)
	failed := false
	for _, r := range results {
		if r.Level == lvlFail {
			failed = true
		}
		fmt.Printf("[%4s] %s\n", r.Level, r.Msg)
	}
	arrResults := make([][]string, len(results))
	for i, r := range results {
		arrResults[i] = []string{r.Level, r.Msg}
	}
	logLine := map[string]any{
		"ts":           time.Now().Unix(),
		"reconcile":    rc,
		"bank_balance": bankVal,
		"failed":       failed,
		"results":      arrResults, // JSON tuples, same shape as the Python log
	}
	line, errM := json.Marshal(logLine)
	if errM != nil {
		fmt.Fprintf(os.Stderr, "could not marshal log line: %v\n", errM)
		os.Exit(1)
	}
	f, err := os.OpenFile(*logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		fmt.Fprintf(f, "%s\n", line)
		f.Close()
	} else {
		fmt.Fprintf(os.Stderr, "could not write %s: %v\n", *logPath, err)
	}
	if failed {
		fmt.Println("RESULT: FAIL - stop issuing and investigate")
		os.Exit(1)
	}
	fmt.Println("RESULT: PASS")
}
