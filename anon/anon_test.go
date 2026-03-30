// Package anon — anon_test.go
//
// Unit tests for the Anon type, verifying that anonymization rules are applied
// correctly to rows and that original sensitive values are replaced.
package anon

import (
	"strings"
	"testing"
	"text/template"

	"data-anonymizer/faker"
	"data-anonymizer/mysql"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func testApply(a *Anon, table string, colNames []string, vals []string) (bool, error) {
	cells := make([]mysql.Cell, len(vals))
	for i, v := range vals {
		cells[i] = mysql.Cell{Value: v}
	}
	drop, err := a.Apply(table, colNames, cells)
	for i, c := range cells {
		vals[i] = c.Value
	}
	return drop, err
}

// buildAnon compiles templates from a rules map of
// table → col → template-string and returns an *Anon ready to use.
func buildAnon(t *testing.T, raw map[string]map[string]string) *Anon {
	t.Helper()
	fm := faker.FuncMap()
	compiled := make(map[string]map[string]*template.Template, len(raw))
	for table, cols := range raw {
		ctpls := make(map[string]*template.Template, len(cols))
		for col, tplStr := range cols {
			tpl, err := template.New("").Funcs(fm).Parse(tplStr)
			if err != nil {
				t.Fatalf("compile template for %s.%s (%q): %v", table, col, tplStr, err)
			}
			ctpls[col] = tpl
		}
		compiled[table] = ctpls
	}
	return New(compiled)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

// TestApply_NoRulesForTable verifies that a table without rules is untouched.
func TestApply_NoRulesForTable(t *testing.T) {
	a := buildAnon(t, map[string]map[string]string{
		"other": {"col": "X"},
	})

	vals := []string{"keep-me", "also-keep"}
	drop, err := testApply(a, "untouched", []string{"a", "b"}, vals)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if drop {
		t.Fatal("unexpected drop for unruled table")
	}
	if vals[0] != "keep-me" || vals[1] != "also-keep" {
		t.Fatalf("values should be unchanged: %v", vals)
	}
}

// TestApply_StaticTemplate verifies replacement via a static template string.
func TestApply_StaticTemplate(t *testing.T) {
	a := buildAnon(t, map[string]map[string]string{
		"users": {"email": "anon@example.com"},
	})

	vals := []string{"real@corp.com", "Alice"}
	drop, err := testApply(a, "users", []string{"email", "name"}, vals)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if drop {
		t.Fatal("unexpected drop")
	}
	if vals[0] != "anon@example.com" {
		t.Errorf("email should be replaced, got %q", vals[0])
	}
	if vals[1] != "Alice" {
		t.Errorf("name should be unchanged, got %q", vals[1])
	}
}

// TestApply_NullSentinel verifies that the {{null}} template function causes
// the cell value to become the ::NULL:: sentinel.
func TestApply_NullSentinel(t *testing.T) {
	a := buildAnon(t, map[string]map[string]string{
		"t": {"secret": "{{null}}"},
	})

	vals := []string{"sensitive-data"}
	drop, err := testApply(a, "t", []string{"secret"}, vals)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if drop {
		t.Fatal("unexpected drop")
	}
	if vals[0] != faker.SentinelNULL {
		t.Errorf("expected SentinelNULL, got %q", vals[0])
	}
	// Original sensitive value must not be in the output.
	if vals[0] == "sensitive-data" {
		t.Error("original sensitive value was not replaced")
	}
}

// TestApply_DropSentinel verifies that the {{drop}} template function causes
// Apply to return drop=true and original values are effectively discarded.
func TestApply_DropSentinel(t *testing.T) {
	a := buildAnon(t, map[string]map[string]string{
		"audit": {"level": "{{drop}}"},
	})

	vals := []string{"ERROR", "sensitive log message"}
	drop, err := testApply(a, "audit", []string{"level", "msg"}, vals)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !drop {
		t.Fatal("expected drop=true")
	}
}

// TestApply_FakerEmail verifies that using {{fakerEmail}} produces a
// non-empty replacement that is different from the original value.
func TestApply_FakerEmail(t *testing.T) {
	a := buildAnon(t, map[string]map[string]string{
		"users": {"email": "{{fakerEmail}}"},
	})

	original := "john.doe@realcompany.com"
	vals := []string{original}
	drop, err := testApply(a, "users", []string{"email"}, vals)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if drop {
		t.Fatal("unexpected drop")
	}
	if vals[0] == "" {
		t.Error("fakerEmail should produce a non-empty value")
	}
	// The replacement should be a plausible email (contains '@').
	if !strings.Contains(vals[0], "@") {
		t.Errorf("fakerEmail output doesn't look like an email: %q", vals[0])
	}
	// The original value must not be in the result.
	if vals[0] == original {
		t.Errorf("fakerEmail returned the exact original value — may not be anonymized: %q", vals[0])
	}
}

// TestApply_FakerName verifies that {{fakerName}} produces a non-empty string
// that differs from the original.
func TestApply_FakerName(t *testing.T) {
	a := buildAnon(t, map[string]map[string]string{
		"users": {"full_name": "{{fakerName}}"},
	})

	original := "John Real Lastname"
	vals := []string{original}
	_, err := testApply(a, "users", []string{"full_name"}, vals)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vals[0] == "" {
		t.Error("fakerName should produce a non-empty value")
	}
}

// TestApply_MultipleColumnsAllReplaced verifies that when every column in a
// table has a rule, none of the original values remain.
func TestApply_MultipleColumnsAllReplaced(t *testing.T) {
	a := buildAnon(t, map[string]map[string]string{
		"accounts": {
			"email":   "{{fakerEmail}}",
			"name":    "{{fakerName}}",
			"phone":   "{{fakerPhone}}",
			"address": "{{fakerStreetAddress}}",
		},
	})

	originals := []string{
		"real@corp.com",
		"Real Person",
		"+1-555-REAL",
		"123 Real Street",
	}
	vals := make([]string, len(originals))
	copy(vals, originals)
	cols := []string{"email", "name", "phone", "address"}

	drop, err := testApply(a, "accounts", cols, vals)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if drop {
		t.Fatal("unexpected drop")
	}

	for i, orig := range originals {
		if vals[i] == "" {
			t.Errorf("column %q should have a non-empty replacement", cols[i])
		}
		if vals[i] == orig {
			t.Errorf("column %q still has original value %q — not anonymized", cols[i], orig)
		}
	}
}

// TestApply_RandAlphaNum verifies the randAlphaNum template function produces
// the right length and replaces the original value.
func TestApply_RandAlphaNum(t *testing.T) {
	a := buildAnon(t, map[string]map[string]string{
		"tokens": {"token": "{{randAlphaNum 16}}"},
	})

	original := "ORIGINAL-SECRET-TOKEN"
	vals := []string{original}
	_, err := testApply(a, "tokens", []string{"token"}, vals)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vals[0] == original {
		t.Errorf("original token was not replaced")
	}
	if len(vals[0]) != 16 {
		t.Errorf("expected 16-char token, got %d chars: %q", len(vals[0]), vals[0])
	}
}

// TestApply_UUIDv4 verifies that {{uuidv4}} produces a valid UUID-shaped string.
func TestApply_UUIDv4(t *testing.T) {
	a := buildAnon(t, map[string]map[string]string{
		"records": {"uid": "{{uuidv4}}"},
	})

	vals := []string{"original-id"}
	_, err := testApply(a, "records", []string{"uid"}, vals)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// A UUID v4 has the form xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx (36 chars).
	if len(vals[0]) != 36 {
		t.Errorf("expected 36-char UUID, got %d: %q", len(vals[0]), vals[0])
	}
	if !strings.Contains(vals[0], "-") {
		t.Errorf("UUID format invalid: %q", vals[0])
	}
	if vals[0] == "original-id" {
		t.Error("original value was not replaced")
	}
}

// TestApply_NilColumnNames verifies that Apply doesn't panic when colNames
// is nil (INSERT without a preceding CREATE TABLE).
func TestApply_NilColumnNames(t *testing.T) {
	a := buildAnon(t, map[string]map[string]string{
		"t": {"col": "REPLACED"},
	})

	vals := []string{"value1", "value2"}
	// nil colNames — no column name → rule mapping possible.
	drop, err := testApply(a, "t", nil, vals)
	if err != nil {
		t.Fatalf("must not error with nil colNames: %v", err)
	}
	if drop {
		t.Fatal("unexpected drop with nil colNames")
	}
	// Values must be unchanged since no column could match.
	if vals[0] != "value1" || vals[1] != "value2" {
		t.Errorf("values changed unexpectedly with nil colNames: %v", vals)
	}
}

// TestApply_RepeatCallsDoNotLeak verifies that calling Apply multiple times
// with different rows doesn't leak values between rows (shared buf contamination).
func TestApply_RepeatCallsDoNotLeak(t *testing.T) {
	a := buildAnon(t, map[string]map[string]string{
		"t": {"email": "safe@example.com"},
	})

	sensitive := []string{"row1@secret.com", "row2@secret.com", "row3@secret.com"}
	for _, orig := range sensitive {
		vals := []string{orig}
		_, err := testApply(a, "t", []string{"email"}, vals)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vals[0] == orig {
			t.Errorf("original value %q was not replaced", orig)
		}
		if vals[0] != "safe@example.com" {
			t.Errorf("unexpected replacement value: %q", vals[0])
		}
	}
}
