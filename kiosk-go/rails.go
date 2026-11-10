// Package main: kiosk-go native BANK RAILS (full port of the retired
// mvp/bank_rail.py to Go, stdlib only, one process, no Python anywhere).
//
// The kiosk IS the payment gateway now. Money can arrive from ANY rail:
//   1) Any gateway webhook  (Razorpay/Cashfree/Stripe/bank API) -> POST /v1/webhook
//   2) Statement CSV export -> -import-csv file.csv -match FUPI
//   3) Lightning via cdk-mintd -> -lightning-mint http://127.0.0.1:3338
//
// Every rail reports inbound payments as (ref, amountInMinorOrUnit); the ref is
// the external payment reference (bank UTR, gateway order id, LN quote id) and
// makes credits idempotent: a replayed ref can never inflate the reserve.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	ErrBadRailInput = fmt.Errorf("bad rail input: amount/ref missing or invalid")
)

// truncate a float for stable display.
func moneyMinor(major float64) float64 { return math.Round(major*100) / 100 }

// ---------------------------------------------------------------------------
// 1) Rail A: gateway/bank WEBHOOK  (handled on the kiosk's own HTTPS mux)
// ---------------------------------------------------------------------------

// webhookProcess parses a verified gateway body and credits the reserve.
// Body: {"amount": <MINOR units paise/cents>, "order_id"/"ref": "<unique>"}
func (k *Kiosk) webhookProcess(raw []byte, docName string) (float64, error) {
	var b webhookBody
	if json.Unmarshal(raw, &b) != nil {
		return 0, ErrBadRailInput
	}
	ref := b.ref()
	if b.Amount <= 0 || ref == "" {
		return 0, ErrBadRailInput
	}
	// Minor units (paise/cents) -> major units. Gateway retries carry the SAME
	// order id, which must never be credited twice: dedupe lives in Deposit.
	reserve, err := k.Deposit(ref, moneyMinor(float64(b.Amount)/100.0))
	if err != nil {
		return 0, err
	}
	log.Printf("[rail:webhook] CREDIT %.2f ref=%s (%s signature OK)",
		moneyMinor(float64(b.Amount)/100.0), ref, docName)
	return reserve, nil
}

type webhookBody struct {
	Amount  int    `json:"amount"`
	OrderID string `json:"order_id,omitempty"`
	Ref     string `json:"ref,omitempty"`
}

func (b webhookBody) ref() string {
	if b.Ref != "" {
		return b.Ref
	}
	return b.OrderID
}

// ---------------------------------------------------------------------------
// 2) Rail B: bank statement CSV import (port of StatementBank)
// ---------------------------------------------------------------------------

// CsvBank imports REAL bank statement CSV exports (HDFC/ICICI/SBI/Chase style).
// Only DEPOSIT (credit) rows count. Every credited row gets an idempotency
// reference: the FUPI remark token from the narration when present
// ("utr:<TOKEN>"), else a hash of the stable columns (date + narration +
// amount) — see depositRefFor. Re-importing the same or an overlapping
// statement therefore cannot credit twice. Rows are skipped when
// narration_match is set and the narration does not contain it (use it so
// salary etc. are never treated as kiosk loads).
func (k *Kiosk) runCsvImport(path, narrationMatch string) (credited float64, okRows int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.Comma = csvSniff(f)
	r.FieldsPerRecord = -1 // headerless rows must not hard-fail
	rows, err := r.ReadAll()
	if err != nil {
		return 0, 0, err
	}
	if len(rows) < 1 {
		return 0, 0, fmt.Errorf("empty CSV")
	}

	header := rows[0]
	depositCol := pickCol(header, "deposit", "credit")
	amountCol := -1 // single-Amount fallback is picked after withdraw lookup
	withdrawCol := pickCol(header, "withdrawal", "withdrawl", "debit")
	if depositCol == -1 {
		amountCol = pickCol(header, "amount")
	}
	if depositCol == -1 && amountCol == -1 {
		return 0, 0, fmt.Errorf("no deposit/credit/amount column recognized in header %q — refusing to import", strings.Join(header, ", "))
	}
	dateCol := pickCol(header, "date", "txn date", "value date", "transaction date")
	descCol := pickCol(header, "narration", "description", "particulars", "remarks", "detail")
	match := strings.ToLower(narrationMatch)

	for _, row := range rows[1:] {
		if len(row) == 0 {
			continue
		}
		if all(row, "") { // blank line
			continue
		}
		amount := 0.0
		if depositCol >= 0 {
			amount = parseMoneyAmount(cell(row, depositCol))
		}
		if amount == 0 && amountCol >= 0 && withdrawCol < 0 {
			amount = parseMoneyAmount(cell(row, amountCol)) // signed single col
		}
		if amount <= 0 {
			continue // debits / withdrawals are never credited
		}
		desc := strings.ToLower(cell(row, descCol))
		if match != "" && !strings.Contains(desc, match) {
			continue // not addressed to the kiosk
		}
		ref := depositRefFor(cell(row, dateCol), desc, amount)
		if _, dup := k.depositRefs[ref]; dup {
			log.Printf("[rail:csv] SKIP already-credited row (%s)", desc)
			continue
		}
		if _, err := k.Deposit(ref, amount); err != nil {
			log.Printf("[rail:csv] REFUSED amount=%.2f: %v", amount, err)
			continue
		}
		credited += amount
		okRows++
		log.Printf("[rail:csv] CREDIT %.2f (%s)", amount, desc)
	}
	log.Printf("[rail:csv] imported total %.2f from %s (%d rows)", credited, path, okRows)
	return credited, okRows, nil
}

func cell(row []string, i int) string {
	if i < 0 || i >= len(row) {
		return ""
	}
	return row[i]
}

func all(ss []string, blank string) bool {
	for _, s := range ss {
		if strings.TrimSpace(s) != blank {
			return false
		}
	}
	return true
}

// csvSniff peeks the first non-empty line and picks , ; or tab like the Python.
func csvSniff(f *os.File) rune {
	br, _ := io.ReadAll(io.LimitReader(f, 4096))
	_, _ = f.Seek(0, io.SeekStart)
	// strip UTF-8 BOM; drop comment lines for the peek only
	text := strings.TrimPrefix(string(br), "\uFEFF")
	var first string
	for _, ln := range strings.SplitN(text, "\n", 1024) {
		line := strings.TrimSpace(ln)
		if line != "" && !strings.HasPrefix(line, ";") && !strings.HasPrefix(line, "#") {
			first = line
			break
		}
	}
	comma, semicolon, bang := strings.Count(first, ","), strings.Count(first, ";"), strings.Count(first, "\t")
	switch {
	case semicolon > comma && semicolon > bang:
		return ';'
	case bang > comma && bang >= semicolon:
		return '\t'
	default:
		return ','
	}
}

// pickCol returns the FIRST column whose lowercased header starts with a stem.
func pickCol(header []string, stems ...string) int {
	norm := make([]string, len(header))
	for i, h := range header {
		norm[i] = strings.Trim(strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == ' ':
				return r
			case r >= 'A' && r <= 'Z':
				return r + ('a' - 'A')
			default:
				return ' '
			}
		}, strings.TrimSpace(h)), " ")
	}
	for _, stem := range stems {
		for i, n := range norm {
			if strings.HasPrefix(n, stem) {
				return i
			}
		}
	}
	return -1
}

var _reDrCr = regexp.MustCompile(`(?i)\s*(cr|dr)\.?$`)

// parseMoneyAmount ports StatementBank._parse_amount:
// "1,234.50", "Rs. 50", "₹ 50.00 Cr" OK.  "-50", "50 DR", "(50)" -> 0.
func parseMoneyAmount(v string) float64 {
	s := strings.TrimSpace(v)
	if s == "" {
		return 0
	}
	s = strings.NewReplacer(",", "", "Rs.", "", "INR", "", "₹", "").Replace(s)
	s = strings.TrimSpace(s)
	up := strings.ToUpper(s)
	if strings.HasSuffix(up, "DR") || strings.HasPrefix(s, "-") ||
		(strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")")) {
		return 0
	}
	s = _reDrCr.ReplaceAllString(s, "")
	s = strings.Trim(s, "+ ")
	x, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	if x > 0 {
		return x
	}
	return 0
}

// depositRefFor builds the idempotency reference for one statement row.
//
// PREFERRED — identity: the FUPI remark token in the narration
// ("FUPI-<UTR/token>", case-insensitive, normalized to upper case). The same
// real deposit then maps to ONE ref across re-exports, column-layout changes
// and formatting drift, and a manual credit that quotes the same token lands
// on the same ref, so the same real money can never be credited twice (the
// bank's own receipt number is the dedupe key).
//
// FALLBACK — stable-column hash: date + narration + deposit amount only,
// NEVER the balance column, so cosmetic re-exports don't remint refs. Two
// genuinely distinct same-day same-amount rows without a token stay deduped
// (safe direction: an under-credit beats an over-credit; include the UTR in
// the remark to get both paid).
func depositRefFor(date, desc string, amount float64) string {
	if tok, ok := fupiRemarkToken(desc); ok {
		return "utr:" + tok
	}
	canonical := strings.Join([]string{strings.TrimSpace(date), strings.TrimSpace(desc), fmt.Sprintf("%.2f", amount)}, "|")
	sum := sha256.Sum256([]byte(canonical))
	return "csv:" + hex.EncodeToString(sum[:16])
}

var fupiTokenRe = regexp.MustCompile(`(?i)FUPI\s*[-_/:. ]\s*([A-Za-z0-9._-]{3,64})`)

// fupiRemarkToken extracts the FUPI-<token> reference from a narration, if any.
func fupiRemarkToken(desc string) (string, bool) {
	m := fupiTokenRe.FindStringSubmatch(desc)
	if m == nil {
		return "", false
	}
	return strings.ToUpper(m[1]), true
}

// ---------------------------------------------------------------------------
// 3) Rail C: Lightning via cdk-mintd (port of LightningMintRail)
// ---------------------------------------------------------------------------

// runLightningPoll creates an invoice at cdk-mintd, blocks polling until it is
// PAID, then credits the reserve. Real money really moves on Lightning; the
// quote id is the external ref and is therefore replay-safe.
func (k *Kiosk) runLightningPoll(mintURL string, amountMinor int, unit string, timeout time.Duration, poll time.Duration) (float64, error) {
	base := strings.TrimRight(mintURL, "/")
	type quoteResp struct {
		Quote   *string `json:"quote"`
		Request string  `json:"request"`
		Invoice string  `json:"invoice"`
		State   any     `json:"state"`
	}

	payload, _ := json.Marshal(map[string]any{
		"amount": amountMinor, "unit": unit, "description": "FUPI kiosk reserve top-up"})
	body, code, err := httpDoJSON(http.MethodPost, base+"/v1/mint/quote/bolt11", payload)
	if err != nil || code != 200 {
		return 0, fmt.Errorf("mint quote request failed (code %d, err %v)", code, err)
	}
	var q quoteResp
	if err := json.Unmarshal(body, &q); err != nil {
		return 0, err
	}
	quote := ""
	if q.Quote != nil {
		quote = *q.Quote
	}
	invoice := q.Request
	if invoice == "" {
		invoice = q.Invoice
	}
	fmt.Printf("  [rail:ln] quote %s\n", quote)
	fmt.Printf("  [rail:ln] PAY THIS INVOICE (real money, real Lightning):\n         %s\n", invoice)

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		gbody, code, err := httpDoJSON(http.MethodGet, base+"/v1/mint/quote/bolt11/"+quote, nil)
		if err == nil && code == 200 {
			if quoteDone(gbody) {
				ml := float64(amountMinor)
				if unit == "usd" || unit == "eur" {
					ml = ml / 100
				}
				amt := moneyMinor(ml)
				if _, err := k.Deposit("ln:"+quote, amt); err != nil {
					return amt, err
				}
				log.Printf("[rail:ln] PAID -> reserve +%.2f %s", amt, unit)
				return amt, nil
			}
		}
		time.Sleep(poll)
	}
	return 0, fmt.Errorf("lightning invoice not paid in time")
}

func quoteDone(b []byte) bool {
	var st struct {
		State any `json:"state"`
	}
	if json.Unmarshal(b, &st) != nil {
		return false
	}
	switch v := st.State.(type) {
	case string:
		return v == "PAID" || v == "ISSUED"
	case float64:
		return v == 2 || v == 3
	}
	return false
}

func httpDoJSON(method, url string, payload []byte) ([]byte, int, error) {
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return body, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}
