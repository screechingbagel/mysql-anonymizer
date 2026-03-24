// Package faker provides fake-data generators used in anonymization templates.
// It wraps gofakeit/v7 and adds custom generators (IBAN, SWIFT, EIN, Invoice).
package faker

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"github.com/brianvoe/gofakeit/v7"
)

// ─── Custom generators not in gofakeit ───────────────────────────────────────

// IBAN returns a fake IBAN-shaped string (XX####################).
func IBAN() string {
	return strings.ToUpper(gofakeit.Lexify("??####################"))
}

// SWIFT returns a fake SWIFT/BIC-shaped string (XXXXXX##).
func SWIFT() string {
	return strings.ToUpper(gofakeit.Lexify("??????##"))
}

// EIN returns a fake US Employer Identification Number (##-#######).
func EIN() string {
	return gofakeit.Numerify("##-#######")
}

// SecondaryAddress returns a fake secondary address (e.g. "Apt. 42").
func SecondaryAddress() string {
	return fmt.Sprintf("Apt. %s", gofakeit.DigitN(3))
}

// ─── Sequential invoice counter ──────────────────────────────────────────────

const invoiceCounterFile = "/tmp/nxs_invoice_seq"
const invoiceBatchSize = 1000

var (
	invoiceMu      sync.Mutex
	invoiceCurrent int
	invoiceMax     int
)

// Invoice returns a unique sequential invoice number, e.g. "INV-00000042".
// Numbers are batched: a batch of 1000 is reserved from the counter file
// at a time so concurrent processes don't collide.
func Invoice() string {
	invoiceMu.Lock()
	defer invoiceMu.Unlock()

	if invoiceCurrent >= invoiceMax {
		start := 0
		if data, err := os.ReadFile(invoiceCounterFile); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				start = n
			}
		}
		invoiceCurrent = start
		invoiceMax = start + invoiceBatchSize
		_ = os.WriteFile(invoiceCounterFile, []byte(strconv.Itoa(invoiceMax)), 0o644)
	}

	val := invoiceCurrent
	invoiceCurrent++
	return fmt.Sprintf("INV-%08d", val)
}

// ─── Template FuncMap ─────────────────────────────────────────────────────────

// Sentinels consumed by anon.Apply to signal special cell behaviour.
const (
	SentinelNULL = "::NULL::"
	SentinelDROP = "::DROP::"
)

var (
	funcMap     template.FuncMap
	funcMapOnce sync.Once
)

// FuncMap returns a text/template.FuncMap with all generators, built once.
// Function names match the template calls in sample-config.conf exactly.
func FuncMap() template.FuncMap {
	funcMapOnce.Do(func() {
		funcMap = template.FuncMap{
			// Sentinels
			"null": func() string { return SentinelNULL },
			"drop": func() string { return SentinelDROP },

			// Names
			"fakerName":      gofakeit.Name,
			"fakerFirstName": gofakeit.FirstName,
			"fakerLastName":  gofakeit.LastName,

			// Contact
			"fakerEmail": gofakeit.Email,
			"fakerPhone": gofakeit.Phone,

			// Address
			"fakerAddress":          func() string { return gofakeit.Address().Address },
			"fakerStreetAddress":    func() string { return gofakeit.Street() },
			"fakerSecondaryAddress": SecondaryAddress,
			"fakerCity":             gofakeit.City,
			"fakerPostcode":         gofakeit.Zip,

			// Company / finance
			"fakerCompany": gofakeit.Company,
			"fakerIBAN":    IBAN,
			"fakerSwift":   SWIFT,
			"fakerEIN":     EIN,

			// Invoice
			"fakerInvoice": Invoice,

			// Identifiers
			"uuidv4": gofakeit.UUID,

			// Random strings — sprig-compatible signatures:
			// {{ randAlphaNum 8 }}  {{ randNumeric 5 }}
			"randAlphaNum": func(n int) string { return gofakeit.LetterN(uint(n)) },
			"randNumeric":  func(n int) string { return gofakeit.DigitN(uint(n)) },

			// String manipulation helpers used in config:
			// {{ randAlphaNum 10 | upper }}
			"upper": strings.ToUpper,
			"lower": strings.ToLower,
		}
	})
	return funcMap
}
