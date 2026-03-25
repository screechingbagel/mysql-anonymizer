// Package mysql — integration_test.go
//
// End-to-end tests that load the committed testdata/integration.conf and run
// the full parser+anonymizer pipeline. They cover every template pattern used:
// faker functions, static strings, {{ null }}, {{ uuidv4 }}, and piped
// transforms such as {{ randAlphaNum 10 | upper }}.
package mysql

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"data-anonymizer/anon"
	"data-anonymizer/config"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// loadTestAnon loads testdata/integration.conf and
// returns an *anon.Anon built from it. Fails the test on any error.
func loadTestAnon(t *testing.T) *anon.Anon {
	t.Helper()
	cfgPath := filepath.Join("testdata", "integration.conf")
	cc, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load test config %q: %v", cfgPath, err)
	}
	return anon.New(cc.Rules)
}

// ddl generates a minimal CREATE TABLE statement.
func ddl(table string, cols ...string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "CREATE TABLE `%s` (\n", table)
	for i, c := range cols {
		sb.WriteString("  `")
		sb.WriteString(c)
		sb.WriteString("` text")
		if i < len(cols)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}
	sb.WriteString(") ENGINE=InnoDB;\n")
	return sb.String()
}

// singleRowInsert builds a single-row INSERT with each value single-quoted.
// Backslashes and single-quotes in values are escaped so the generated SQL is
// valid input for the parser (mirrors what mysqldump produces).
func singleRowInsert(table string, vals ...string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "INSERT INTO `%s` VALUES (", table)
	for i, v := range vals {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteByte('\'')
		v = strings.ReplaceAll(v, `\`, `\\`)
		v = strings.ReplaceAll(v, `'`, `\'`)
		sb.WriteString(v)
		sb.WriteByte('\'')
	}
	sb.WriteString(");\n")
	return sb.String()
}

// runWithTestConfig parses input using the committed testdata/integration.conf.
func runWithTestConfig(t *testing.T, input string) string {
	t.Helper()
	return run(t, input, loadTestAnon(t))
}

// ─── Integration tests ────────────────────────────────────────────────────────

// TestIntegration_UsersTable verifies all PII columns in the `users` table
// are replaced and the most sensitive values (password, token, location)
// are either nullified or replaced with safe static values.
func TestIntegration_UsersTable(t *testing.T) {
	cols := []string{
		"first_name", "last_name", "full_name",
		"email", "phone",
		"password_hash", "ip_address", "session_token", "avatar_url",
		"oauth_token", "lat", "lng",
	}
	sensitiveVals := []string{
		"John", "Smith", "John Smith",
		"john.smith@realco.com", "+1-555-0001",
		"plaintext-password!", "203.0.113.42", "real-secret-token-xyz", "https://realcdn.com/p.jpg",
		"oauth-live-tok-abc123", "40.7128", "-74.0060",
	}

	input := ddl("users", cols...) + singleRowInsert("users", sensitiveVals...)
	got := runWithTestConfig(t, input)

	// All real PII must be gone.
	mustNotContain(t, got,
		"john.smith@realco.com",
		"plaintext-password!",
		"203.0.113.42",
		"real-secret-token-xyz",
		"oauth-live-tok-abc123",
		"40.7128", "-74.0060",
	)

	// Static replacements must be present.
	mustContain(t, got,
		"$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
		"127.0.0.1",
		"https://example.com/avatar.png",
	)

	// oauth_token, lat, lng → NULL.
	nullCount := strings.Count(got, "NULL")
	if nullCount < 3 {
		t.Errorf("expected ≥3 NULLs (oauth_token/lat/lng), got %d\noutput:\n%s", nullCount, got)
	}
}

// TestIntegration_PaymentCredentialsAllNulled verifies that every column in
// the payment_credentials table — which holds live gateway credentials — is
// rendered as SQL NULL. This is the highest-risk table.
func TestIntegration_PaymentCredentialsAllNulled(t *testing.T) {
	cols := []string{
		"api_username", "api_password", "api_key",
		"api_secret", "merchant_id", "terminal_id", "meta",
	}
	sensitiveVals := []string{
		"prod-user-X9Z", "s3cr3tP@ss!", "api-key-live-abc",
		"api-secret-live-xyz", "MID-999888", "TERM-001", `{"prod":"data"}`,
	}

	input := ddl("payment_credentials", cols...) +
		singleRowInsert("payment_credentials", sensitiveVals...)
	got := runWithTestConfig(t, input)

	// Every credential must be gone.
	mustNotContain(t, got,
		"prod-user-X9Z", "s3cr3tP@ss!", "api-key-live-abc",
		"api-secret-live-xyz", "MID-999888", "TERM-001",
	)

	// All 7 columns → NULL.
	nullCount := strings.Count(got, "NULL")
	if nullCount < 7 {
		t.Errorf("expected 7 NULLs for all credential columns, got %d\noutput:\n%s", nullCount, got)
	}
}

// TestIntegration_TransactionsTable verifies financial PII is replaced and
// the most sensitive fields (card_token, raw_response) are nullified.
func TestIntegration_TransactionsTable(t *testing.T) {
	cols := []string{
		"invoice_no", "payer_name", "payer_email", "payer_phone",
		"billing_address", "billing_city", "billing_postcode",
		"ip_address", "authorization_code", "transaction_id",
		"card_token", "card_expiry", "raw_response",
		"account_holder", "bank_name", "cheque_no", "comment",
	}
	sensitiveVals := []string{
		"INV-REAL-9999", "Jane Doe", "jane@realco.com", "+1-212-555-0001",
		"123 Main St", "New York", "10001",
		"198.51.100.42", "AUTHCODE-REAL-XYZ", "txn-real-uuid-1234",
		"card-tok-real-9999", "12/25", `{"auth":"real_response"}`,
		"Jane Doe", "Real Bank", "100200", "Real comment",
	}

	input := ddl("transactions", cols...) + singleRowInsert("transactions", sensitiveVals...)
	got := runWithTestConfig(t, input)

	mustNotContain(t, got,
		"jane@realco.com",
		"198.51.100.42",
		"AUTHCODE-REAL-XYZ",
		"txn-real-uuid-1234",
		"card-tok-real-9999",
	)

	// Static replacements.
	mustContain(t, got, "127.0.0.1", "12/99")

	// card_token + raw_response → NULL.
	nullCount := strings.Count(got, "NULL")
	if nullCount < 2 {
		t.Errorf("expected ≥2 NULLs (card_token/raw_response), got %d\noutput:\n%s", nullCount, got)
	}
}

// TestIntegration_AuthorizationCodeFormat verifies the
// {{ randAlphaNum 10 | upper }} pipeline — output must be exactly 10
// uppercase alphanumeric characters.
func TestIntegration_AuthorizationCodeFormat(t *testing.T) {
	cols := []string{
		"invoice_no", "payer_name", "payer_email", "payer_phone",
		"billing_address", "billing_city", "billing_postcode",
		"ip_address", "authorization_code", "transaction_id",
		"card_token", "card_expiry", "raw_response",
		"account_holder", "bank_name", "cheque_no", "comment",
	}
	vals := make([]string, len(cols))
	for i, c := range cols {
		vals[i] = "original-" + c
	}

	input := ddl("transactions", cols...) + singleRowInsert("transactions", vals...)
	got := runWithTestConfig(t, input)

	mustNotContain(t, got, "original-authorization_code")

	// Find the replacement: scan quoted tokens for a 10-char all-upper alphanumeric.
	found := false
	for part := range strings.SplitSeq(got, "'") {
		if len(part) != 10 {
			continue
		}
		allUpperAlphaNum := true
		for _, ch := range part {
			if (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') {
				allUpperAlphaNum = false
				break
			}
		}
		if allUpperAlphaNum {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no 10-char uppercase alphanumeric authorization_code in output:\n%s", got)
	}
}

// TestIntegration_IntegrationSecretsNulled verifies that webhook secrets and
// credentials JSON are nullified while the uuid column is replaced.
func TestIntegration_IntegrationSecretsNulled(t *testing.T) {
	cols := []string{"credentials_json", "webhook_secret", "integration_uuid"}
	sensitiveVals := []string{
		`{"stripe_secret":"sk_live_real"}`,
		"whsec_realkey_abc123",
		"original-uuid-here",
	}

	input := ddl("integration_secrets", cols...) +
		singleRowInsert("integration_secrets", sensitiveVals...)
	got := runWithTestConfig(t, input)

	mustNotContain(t, got, "sk_live_real", "whsec_realkey_abc123", "original-uuid-here")

	// The two credential columns → NULL.
	nullCount := strings.Count(got, "NULL")
	if nullCount < 2 {
		t.Errorf("expected ≥2 NULLs for integration_secrets, got %d\noutput:\n%s", nullCount, got)
	}
}

// TestIntegration_MultiTableDump simulates a multi-table dump: configured
// tables are anonymized, unconfigured tables pass through untouched.
func TestIntegration_MultiTableDump(t *testing.T) {
	// Configured table.
	usersDDL := ddl("users",
		"first_name", "last_name", "full_name",
		"email", "phone",
		"password_hash", "ip_address", "session_token", "avatar_url",
		"oauth_token", "lat", "lng",
	)
	usersInsert := singleRowInsert("users",
		"Alice", "Real", "Alice Real",
		"alice@realco.com", "+1-555-1111",
		"PlaintextPass!", "1.2.3.4", "super-secret-session", "https://cdn.real/p.jpg",
		"oauth-tok-real", "34.0522", "-118.2437",
	)

	// Unconfigured table — must pass through unchanged.
	auditDDL := ddl("audit_log", "id", "action", "actor")
	auditInsert := singleRowInsert("audit_log", "42", "LOGIN", "sysadmin@internal.com")

	input := usersDDL + usersInsert + auditDDL + auditInsert
	got := runWithTestConfig(t, input)

	// PII from configured table must be gone.
	mustNotContain(t, got,
		"alice@realco.com",
		"PlaintextPass!",
		"super-secret-session",
		"oauth-tok-real",
	)

	// Unconfigured table must survive intact.
	mustContain(t, got, "sysadmin@internal.com", "LOGIN")

	// Static replacements must appear.
	mustContain(t, got,
		"127.0.0.1",
		"$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi",
	)
}

// TestIntegration_UnsubscribeList verifies that email addresses in the
// unsubscribe_list table are replaced.
func TestIntegration_UnsubscribeList(t *testing.T) {
	input := ddl("unsubscribe_list", "email") +
		singleRowInsert("unsubscribe_list", "donotmail@realco.com")
	got := runWithTestConfig(t, input)

	mustNotContain(t, got, "donotmail@realco.com")

	// Replacement must look like an email.
	if strings.Count(got, "@") == 0 {
		t.Errorf("expected a replacement email in output:\n%s", got)
	}
}

// TestIntegration_ColumnNotInConfigPassesThrough verifies that columns absent
// from the config are not anonymized, even when the table is configured.
// This catches accidental over-reach.
func TestIntegration_ColumnNotInConfigPassesThrough(t *testing.T) {
	// Columns "id" and "created_at" are not in the users config.
	cols := []string{
		"id", "created_at",
		"first_name", "last_name", "full_name",
		"email", "phone",
		"password_hash", "ip_address", "session_token", "avatar_url",
		"oauth_token", "lat", "lng",
	}
	vals := make([]string, len(cols))
	vals[0] = "12345"
	vals[1] = "2024-01-15 10:30:00"
	for i := 2; i < len(vals); i++ {
		vals[i] = "SENSITIVE-" + cols[i]
	}

	input := ddl("users", cols...) + singleRowInsert("users", vals...)
	got := runWithTestConfig(t, input)

	// Non-configured columns must survive.
	mustContain(t, got, "12345", "2024-01-15 10:30:00")

	// Configured sensitive columns must be replaced.
	mustNotContain(t, got, "SENSITIVE-email", "SENSITIVE-password_hash", "SENSITIVE-session_token")
}
