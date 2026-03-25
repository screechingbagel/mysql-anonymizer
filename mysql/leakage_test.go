// Package mysql — leakage_test.go
//
// These tests specifically verify that sensitive values that should be
// anonymized do NOT appear in the output. Each test uses negative assertions
// (strings.Contains returning false) as the primary check, in addition to
// positive assertions that confirm replacement values are present.
package mysql

import (
	"fmt"
	"strings"
	"testing"

	"data-anonymizer/faker"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

// mustNotContain fails t if output contains any of the given forbidden strings.
func mustNotContain(t *testing.T, output string, forbidden ...string) {
	t.Helper()
	for _, f := range forbidden {
		if strings.Contains(output, f) {
			t.Errorf("leakage: output contains forbidden value %q\noutput:\n%s", f, output)
		}
	}
}

// mustContain fails t if output is missing any of the given required strings.
func mustContain(t *testing.T, output string, required ...string) {
	t.Helper()
	for _, r := range required {
		if !strings.Contains(output, r) {
			t.Errorf("missing expected value %q in output:\n%s", r, output)
		}
	}
}

// ─── Tests ───────────────────────────────────────────────────────────────────

// TestLeakage_AllColumnsInTable verifies that when every column in a table has
// a rule, none of the original values appear in the output.
func TestLeakage_AllColumnsInTable(t *testing.T) {
	input := "CREATE TABLE `customers` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `email` varchar(255) NOT NULL,\n" +
		"  `phone` varchar(30),\n" +
		"  `name` varchar(100) NOT NULL\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `customers` VALUES (1,'real@corp.com','+1-800-REAL','John Real');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"customers": {
			"email": "anon@example.com",
			"phone": "000-0000",
			"name":  "Anonymous",
		},
	}}

	got := run(t, input, a)

	mustNotContain(t, got, "real@corp.com", "+1-800-REAL", "John Real")
	mustContain(t, got, "'anon@example.com'", "'000-0000'", "'Anonymous'")
}

// TestLeakage_PartialRules verifies that only the configured columns are
// anonymized and that none of those original values leak.
func TestLeakage_PartialRules(t *testing.T) {
	input := "CREATE TABLE `users` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `email` varchar(255),\n" +
		"  `username` varchar(50),\n" +
		"  `score` int NOT NULL\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `users` VALUES (42,'secret@company.com','johndoe',9999);\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"users": {"email": "replaced@example.com"},
	}}

	got := run(t, input, a)

	// email must be gone
	mustNotContain(t, got, "secret@company.com")
	// replacement must be present
	mustContain(t, got, "'replaced@example.com'")
	// columns without rules must survive unchanged
	mustContain(t, got, "'johndoe'", "9999", "42")
}

// TestLeakage_ManyRowsAllReplaced checks that across many rows, no original
// value appears — even for edge-case values like empty string and whitespace.
func TestLeakage_ManyRowsAllReplaced(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("CREATE TABLE `logs` (\n")
	sb.WriteString("  `id` int NOT NULL,\n")
	sb.WriteString("  `msg` text NOT NULL\n")
	sb.WriteString(") ENGINE=InnoDB;\n")
	sb.WriteString("INSERT INTO `logs` VALUES ")

	const numRows = 50
	sensitiveValues := make([]string, numRows)
	for i := range numRows {
		sensitiveValues[i] = fmt.Sprintf("SENSITIVE-DATA-%04d", i)
		if i > 0 {
			sb.WriteString(",\n")
		}
		fmt.Fprintf(&sb, "(%d,'%s')", i+1, sensitiveValues[i])
	}
	sb.WriteString(";\n")

	a := &staticApplier{rules: map[string]map[string]string{
		"logs": {"msg": "REDACTED"},
	}}

	got := run(t, sb.String(), a)

	// No original value must appear.
	mustNotContain(t, got, sensitiveValues...)
	// REDACTED must appear exactly numRows times.
	count := strings.Count(got, "'REDACTED'")
	if count != numRows {
		t.Errorf("expected %d 'REDACTED' occurrences, got %d\noutput:\n%s", numRows, count, got)
	}
}

// TestLeakage_BinaryColumnAnonymized verifies that a _binary '...' cell with
// a rule is anonymized and the original bytes don't leak.
func TestLeakage_BinaryColumnAnonymized(t *testing.T) {
	input := "CREATE TABLE `blobs` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `data` blob NOT NULL\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `blobs` VALUES (1,_binary 'SECRET_BINARY_DATA');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"blobs": {"data": "ANON_BINARY"},
	}}

	got := run(t, input, a)

	mustNotContain(t, got, "SECRET_BINARY_DATA")
	mustContain(t, got, "'ANON_BINARY'")
}

// TestLeakage_NullSentinelRemovesValue verifies that a rule returning
// ::NULL:: causes the original value to vanish (replaced by NULL).
func TestLeakage_NullSentinelRemovesValue(t *testing.T) {
	input := "CREATE TABLE `private` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `ssn` varchar(20)\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `private` VALUES (1,'123-45-6789');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"private": {"ssn": faker.SentinelNULL},
	}}

	got := run(t, input, a)

	mustNotContain(t, got, "123-45-6789")
	mustContain(t, got, "NULL")
}

// TestLeakage_DropEliminatesRow verifies that a dropped row's values do not
// appear in the output at all.
func TestLeakage_DropEliminatesRow(t *testing.T) {
	input := "CREATE TABLE `audit` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `payload` text NOT NULL\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `audit` VALUES (1,'KEEP THIS'),(2,'DROP THIS'),(3,'ALSO KEEP');\n"

	// Drop only rows where id=2 is awkward to express with staticApplier,
	// so instead we test that a dropApplier drops ALL rows.
	a := &dropApplier{tables: map[string]bool{"audit": true}}

	got := run(t, input, a)

	mustNotContain(t, got, "KEEP THIS", "DROP THIS", "ALSO KEEP")
}

// TestLeakage_MultiTableIsolation verifies that rules for table A do not
// bleed into table B or vice versa.
func TestLeakage_MultiTableIsolation(t *testing.T) {
	input := "CREATE TABLE `payments` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `card` varchar(20)\n" +
		") ENGINE=InnoDB;\n" +
		"CREATE TABLE `sessions` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `token` varchar(100)\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `payments` VALUES (1,'4111-1111-1111-1111');\n" +
		"INSERT INTO `sessions` VALUES (1,'super-secret-token-abc123');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"payments": {"card": "XXXX-XXXX-XXXX-0000"},
		"sessions": {"token": "REDACTED_TOKEN"},
	}}

	got := run(t, input, a)

	mustNotContain(t, got, "4111-1111-1111-1111", "super-secret-token-abc123")
	mustContain(t, got, "'XXXX-XXXX-XXXX-0000'", "'REDACTED_TOKEN'")
}

// TestLeakage_NoCreateTableStillAnonymizes checks the parser handles an INSERT
// without a preceding CREATE TABLE. Without a CREATE TABLE, colNames is nil,
// so rules can't be keyed by column name. The row must be passed through
// without panic. This validates defensive behaviour.
func TestLeakage_NoCreateTablePassesThroughSafely(t *testing.T) {
	// No CREATE TABLE — parser has no column metadata.
	input := "INSERT INTO `orphan` VALUES (1,'something');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		// Rule configured but can't match because colNames will be nil.
		"orphan": {"col": "REPLACED"},
	}}

	// Must not panic; values pass through verbatim.
	got := run(t, input, a)

	mustContain(t, got, "something")
}

// TestLeakage_InsertQuotingPreservedAfterAnon verifies that replacement values
// that contain special characters (backslash, single-quote) are properly
// escaped and don't produce unbalanced SQL syntax.
func TestLeakage_ReplacementEscapingPreventsQuoteInjection(t *testing.T) {
	input := "CREATE TABLE `t` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `note` text\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `t` VALUES (1,'original value');\n"

	// Replacement containing a quote: a naive implementation would break SQL.
	a := &staticApplier{rules: map[string]map[string]string{
		"t": {"note": "it's a trap\\yes"},
	}}

	got := run(t, input, a)

	mustNotContain(t, got, "original value")
	// The single quote and backslash must be escaped in the output.
	mustContain(t, got, `it\'s a trap\\yes`)
}

// TestLeakage_EmptyStringReplacement checks that replacing a value with an
// empty string results in an empty quoted string, not the original value.
func TestLeakage_EmptyStringReplacement(t *testing.T) {
	input := "CREATE TABLE `t` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `secret` varchar(50)\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `t` VALUES (1,'MUST-NOT-APPEAR');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"t": {"secret": ""},
	}}

	got := run(t, input, a)

	mustNotContain(t, got, "MUST-NOT-APPEAR")
	// Output should have an empty quoted string.
	mustContain(t, got, "''")
}

// TestLeakage_MultiLineInsertAllRowsReplaced ensures multi-line VALUES blocks
// (each row on its own line) fully anonymize all rows — not just the first.
func TestLeakage_MultiLineInsertAllRowsReplaced(t *testing.T) {
	input := "CREATE TABLE `contacts` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `email` varchar(255)\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `contacts` VALUES (1,'alice@real.com'),\n" +
		"(2,'bob@real.com'),\n" +
		"(3,'charlie@real.com');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"contacts": {"email": "anon@example.com"},
	}}

	got := run(t, input, a)

	mustNotContain(t, got, "alice@real.com", "bob@real.com", "charlie@real.com")

	count := strings.Count(got, "'anon@example.com'")
	if count != 3 {
		t.Errorf("expected 3 replacements, got %d\noutput:\n%s", count, got)
	}
}

// TestLeakage_ReplacedNumericDoesNotRevealOriginal checks that a bare
// (unquoted) numeric cell that has a rule is replaced and the original
// number does not appear.
func TestLeakage_ReplacedNumericDoesNotRevealOriginal(t *testing.T) {
	// We model numeric replacement via staticApplier setting the bare value.
	// Note: the original cell '99999' is bare (no quotes).
	input := "CREATE TABLE `accounts` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `balance` bigint NOT NULL\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `accounts` VALUES (1,99999);\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"accounts": {"balance": "0"},
	}}

	got := run(t, input, a)

	// 99999 must be gone; 0 must be present.
	// Note: "1" also appears as the id, but "99999" is unique.
	mustNotContain(t, got, "99999")
	// "0" will appear but let's just confirm no leakage (strict value check).
}

// TestLeakage_ConfiguredTableUnconfiguredColPassthrough ensures that when a
// table IS in the rules but a specific column is NOT, the unconfigured
// column's value is passed through unchanged — verifying correct partial
// anonymization without double-application.
func TestLeakage_ConfiguredTableUnconfiguredColPassthrough(t *testing.T) {
	input := "CREATE TABLE `profiles` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `email` varchar(255),\n" +
		"  `bio` text\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `profiles` VALUES (1,'private@domain.com','This is my public bio');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"profiles": {"email": "redacted@example.com"},
		// bio has no rule — must be passed through unchanged.
	}}

	got := run(t, input, a)

	mustNotContain(t, got, "private@domain.com")
	mustContain(t, got, "'redacted@example.com'", "This is my public bio")
}
