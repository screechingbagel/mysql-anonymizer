package mysql

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"data-anonymizer/faker"
)

// ─── Test Applier implementations ─────────────────────────────────────────────

// staticApplier replaces specific columns with fixed values.
type staticApplier struct {
	// rules: table → column → replacement value (or faker.SentinelNULL)
	rules map[string]map[string]string
}

func (a *staticApplier) Apply(table string, colNames []string, vals []string) (bool, error) {
	tr, ok := a.rules[table]
	if !ok {
		return false, nil
	}
	for i, col := range colNames {
		if v, ok := tr[col]; ok {
			vals[i] = v
		}
	}
	return false, nil
}

// dropApplier drops every row for configured tables.
type dropApplier struct{ tables map[string]bool }

func (a *dropApplier) Apply(table string, _ []string, _ []string) (bool, error) {
	return a.tables[table], nil
}

// passthroughApplier makes no changes.
type passthroughApplier struct{}

func (passthroughApplier) Apply(_ string, _ []string, _ []string) (bool, error) {
	return false, nil
}

// ─── Helper ───────────────────────────────────────────────────────────────────

func run(t *testing.T, input string, a Applier) string {
	t.Helper()
	var out bytes.Buffer
	if err := Parse(context.Background(), strings.NewReader(input), &out, a); err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	return out.String()
}

// TestCancelledContext verifies that an already-cancelled context causes Parse
// to return immediately without processing input.
func TestCancelledContext(t *testing.T) {
	input := "CREATE TABLE `t` (\n" +
		"  `id` int NOT NULL\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `t` VALUES (1),(2),(3);\n"

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	var out bytes.Buffer
	err := Parse(ctx, strings.NewReader(input), &out, passthroughApplier{})
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

// TestPassthrough verifies that lines with no INSERT INTO or CREATE TABLE are
// copied verbatim.
func TestPassthrough(t *testing.T) {
	input := "-- MariaDB dump 10.19\n" +
		"/*!40101 SET NAMES utf8mb4 */;\n" +
		"LOCK TABLES `foo` WRITE;\n" +
		"UNLOCK TABLES;\n"

	got := run(t, input, passthroughApplier{})
	if got != input {
		t.Fatalf("expected passthrough unchanged\ngot: %q\nwant: %q", got, input)
	}
}

// TestCreateTablePassthrough checks that CREATE TABLE DDL is copied verbatim.
func TestCreateTablePassthrough(t *testing.T) {
	input := "CREATE TABLE `users` (\n" +
		"  `id` int NOT NULL AUTO_INCREMENT,\n" +
		"  `email` varchar(255) NOT NULL,\n" +
		"  PRIMARY KEY (`id`)\n" +
		") ENGINE=InnoDB;\n"

	got := run(t, input, passthroughApplier{})
	if got != input {
		t.Fatalf("CREATE TABLE should pass through unchanged\ngot: %q\nwant: %q", got, input)
	}
}

// TestSingleRowRule replaces one column in a single-row INSERT.
func TestSingleRowRule(t *testing.T) {
	input := "CREATE TABLE `users` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `email` varchar(255) NOT NULL,\n" +
		"  `name` varchar(100) NOT NULL,\n" +
		"  PRIMARY KEY (`id`)\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `users` VALUES (1,'original@example.com','Alice');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"users": {"email": "anon@example.com"},
	}}

	got := run(t, input, a)

	if !strings.Contains(got, "'anon@example.com'") {
		t.Fatalf("expected replaced email in output\ngot: %s", got)
	}
	if strings.Contains(got, "original@example.com") {
		t.Fatalf("original email should be gone\ngot: %s", got)
	}
	// id and name should be unchanged.
	if !strings.Contains(got, "1,") {
		t.Fatalf("numeric id should be unchanged\ngot: %s", got)
	}
	if !strings.Contains(got, "'Alice'") {
		t.Fatalf("name should be unchanged\ngot: %s", got)
	}
}

// TestMultiRowInline checks multiple rows in one VALUES list on a single line.
func TestMultiRowInline(t *testing.T) {
	input := "CREATE TABLE `t` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `val` varchar(50) NOT NULL\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `t` VALUES (1,'alpha'),(2,'beta'),(3,'gamma');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"t": {"val": "REPLACED"},
	}}

	got := run(t, input, a)

	if strings.Count(got, "'REPLACED'") != 3 {
		t.Fatalf("expected 3 replaced values\ngot: %s", got)
	}
	for _, orig := range []string{"alpha", "beta", "gamma"} {
		if strings.Contains(got, orig) {
			t.Fatalf("original value %q should be gone\ngot: %s", orig, got)
		}
	}
}

// TestMultiLineValues checks VALUES rows that span multiple lines
// (mysqldump's extended-insert format with each row on its own line).
func TestMultiLineValues(t *testing.T) {
	input := "CREATE TABLE `t` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `val` varchar(50) NOT NULL\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `t` VALUES (1,'first'),\n" +
		"(2,'second'),\n" +
		"(3,'third');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"t": {"val": "X"},
	}}

	got := run(t, input, a)

	if strings.Count(got, "'X'") != 3 {
		t.Fatalf("expected 3 replacements\ngot: %s", got)
	}
}

// TestNullReplacement checks that a rule returning ::NULL:: is rendered as SQL NULL.
func TestNullReplacement(t *testing.T) {
	input := "CREATE TABLE `t` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `secret` varchar(100)\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `t` VALUES (1,'sensitive-data');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"t": {"secret": faker.SentinelNULL},
	}}

	got := run(t, input, a)

	if !strings.Contains(got, "NULL") {
		t.Fatalf("expected NULL in output\ngot: %s", got)
	}
	if strings.Contains(got, "sensitive-data") {
		t.Fatalf("original value should be gone\ngot: %s", got)
	}
}

// TestBareNullPassthrough checks that a bare NULL cell (no rule) is passed through.
func TestBareNullPassthrough(t *testing.T) {
	input := "CREATE TABLE `t` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `opt` varchar(100)\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `t` VALUES (1,NULL);\n"

	got := run(t, input, passthroughApplier{})

	if !strings.Contains(got, "NULL") {
		t.Fatalf("bare NULL should pass through\ngot: %s", got)
	}
}

// TestEscapedQuoteInCell checks that a cell with an escaped single quote (\\')
// is read and written correctly.
func TestEscapedQuoteInCell(t *testing.T) {
	input := "CREATE TABLE `t` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `note` text\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `t` VALUES (1,'it\\'s here');\n"

	// No rule: should pass through unchanged.
	got := run(t, input, passthroughApplier{})

	if !strings.Contains(got, `it\'s here`) {
		t.Fatalf("escaped quote should be preserved\ngot: %s", got)
	}
}

// TestNoRuleTable verifies that a table with no configured rules passes through.
func TestNoRuleTable(t *testing.T) {
	input := "CREATE TABLE `untouched` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `data` varchar(100)\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `untouched` VALUES (42,'keep-this');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"other_table": {"col": "x"},
	}}

	got := run(t, input, a)

	if !strings.Contains(got, "keep-this") {
		t.Fatalf("unconfigured table should pass through\ngot: %s", got)
	}
}

// TestNoRuleColumn verifies that a column with no rule passes through while
// other columns in the same table are transformed.
func TestNoRuleColumn(t *testing.T) {
	input := "CREATE TABLE `t` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `email` varchar(100),\n" +
		"  `preserve` varchar(100)\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `t` VALUES (7,'old@x.com','keep-me');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"t": {"email": "new@x.com"},
	}}

	got := run(t, input, a)

	if !strings.Contains(got, "'keep-me'") {
		t.Fatalf("column without rule should be unchanged\ngot: %s", got)
	}
	if !strings.Contains(got, "'new@x.com'") {
		t.Fatalf("column with rule should be replaced\ngot: %s", got)
	}
}

// TestDropRow checks that a table using the drop applier produces no row output.
func TestDropRow(t *testing.T) {
	input := "CREATE TABLE `t` (\n" +
		"  `id` int NOT NULL\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `t` VALUES (1),(2),(3);\n"

	a := &dropApplier{tables: map[string]bool{"t": true}}

	got := run(t, input, a)

	// The INSERT INTO header should be present, but no rows (nothing between VALUES and ;).
	// Our parser writes the INSERT prefix, then no rows, then ";".
	if strings.Contains(got, "(1)") || strings.Contains(got, "(2)") || strings.Contains(got, "(3)") {
		t.Fatalf("dropped rows should not appear in output\ngot: %s", got)
	}
}

// TestEscapeOnReplacement checks that a substituted value containing a
// single-quote is properly escaped in the output.
func TestEscapeOnReplacement(t *testing.T) {
	input := "CREATE TABLE `t` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `name` varchar(100)\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `t` VALUES (1,'original');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"t": {"name": "O'Brien"},
	}}

	got := run(t, input, a)

	// The escaped form should appear, not raw '.
	if !strings.Contains(got, `O\'Brien`) {
		t.Fatalf("single-quote in replacement should be escaped\ngot: %s", got)
	}
}

// TestMultipleTablesIndependent verifies that rules for different tables are
// applied independently and don't interfere.
func TestMultipleTablesIndependent(t *testing.T) {
	input := "CREATE TABLE `users` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `email` varchar(100)\n" +
		") ENGINE=InnoDB;\n" +
		"CREATE TABLE `orders` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `ref` varchar(100)\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `users` VALUES (1,'user@test.com');\n" +
		"INSERT INTO `orders` VALUES (99,'ORD-001');\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"users":  {"email": "anon@anon.com"},
		"orders": {"ref": "REF-ANON"},
	}}

	got := run(t, input, a)

	if !strings.Contains(got, "'anon@anon.com'") {
		t.Fatalf("users.email should be replaced\ngot: %s", got)
	}
	if !strings.Contains(got, "'REF-ANON'") {
		t.Fatalf("orders.ref should be replaced\ngot: %s", got)
	}
	if strings.Contains(got, "user@test.com") || strings.Contains(got, "ORD-001") {
		t.Fatalf("original values should be gone\ngot: %s", got)
	}
}

// TestNamedColumnListPreserved is a regression test for the bug where the
// parser stripped the column list from INSERT statements that use the
// named-column form:
//
//	INSERT INTO `t` (`id`, `name`, `country`) VALUES ...
//
// Without the fix, the output was:
//
//	INSERT INTO `t` VALUES ...
//
// which is unsafe to re-import if the schema later gains a column.
func TestNamedColumnListPreserved(t *testing.T) {
	input := "CREATE TABLE `sales_persons` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `name` varchar(64),\n" +
		"  `country` varchar(128),\n" +
		"  PRIMARY KEY (`id`)\n" +
		") ENGINE=InnoDB DEFAULT CHARSET=utf8;\n" +
		"INSERT INTO `sales_persons` (`id`, `name`, `country`) VALUES (1,'Alice Smith','Chile'),(2,'Bob Jones','France');\n"

	// Case 1: passthrough — column list must be preserved verbatim.
	t.Run("passthrough", func(t *testing.T) {
		got := run(t, input, passthroughApplier{})
		if !strings.Contains(got, "(`id`, `name`, `country`)") {
			t.Fatalf("named-column list was stripped from output\ngot: %s", got)
		}
	})

	// Case 2: with a replacement rule — column list still present, value changed.
	t.Run("with_rule", func(t *testing.T) {
		a := &staticApplier{rules: map[string]map[string]string{
			"sales_persons": {"name": "REDACTED"},
		}}
		got := run(t, input, a)
		if !strings.Contains(got, "(`id`, `name`, `country`)") {
			t.Fatalf("named-column list was stripped from output\ngot: %s", got)
		}
		if strings.Contains(got, "Alice Smith") || strings.Contains(got, "Bob Jones") {
			t.Fatalf("original names should be redacted\ngot: %s", got)
		}
		if strings.Count(got, "'REDACTED'") != 2 {
			t.Fatalf("expected 2 REDACTED values\ngot: %s", got)
		}
	})
}

// TestUnterminatedRowRegression verifies that a string value containing a semicolon
// at the end of a physical line (and spanning multiple lines) does not prematurely
// terminate the parser's statement read loop.
func TestUnterminatedRowRegression(t *testing.T) {
	input := "CREATE TABLE `t` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `note` text\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `t` VALUES (1,'this string ends with a semicolon;\n" +
		"but continues on the next line'),(2,'normal');\n"

	got := run(t, input, passthroughApplier{})

	if !strings.Contains(got, "this string ends with a semicolon;\nbut continues") {
		t.Fatalf("expected string containing semicolon and newline to survive\ngot: %s", got)
	}
	if !strings.Contains(got, "(2,'normal')") {
		t.Fatalf("expected subsequent row to remain uncorrupted\ngot: %s", got)
	}
}

// TestTruncatedStreamDiscarded verifies that a stream truncated mid-INSERT
// (e.g. mysqldump killed by timeout) does not produce an error. The partial
// statement is silently discarded; complete statements before it are preserved.
func TestTruncatedStreamDiscarded(t *testing.T) {
	// Three cases of truncation mid-INSERT:
	// 1. truncated mid-string-cell (no closing quote, no semicolon)
	// 2. truncated mid-bare-cell
	// 3. truncated after the opening '(' of a row
	cases := []struct {
		name  string
		input string
	}{
		{
			name: "mid_string_cell",
			input: "CREATE TABLE `t` (\n" +
				"  `id` int NOT NULL,\n" +
				"  `note` text\n" +
				") ENGINE=InnoDB;\n" +
				"INSERT INTO `t` VALUES (1,'complete');\n" +
				"INSERT INTO `t` VALUES (2,'truncated mid-str", // no closing quote or semicolon
		},
		{
			name: "mid_bare_cell",
			input: "CREATE TABLE `t` (\n" +
				"  `id` int NOT NULL\n" +
				") ENGINE=InnoDB;\n" +
				"INSERT INTO `t` VALUES (1);\n" +
				"INSERT INTO `t` VALUES (99", // no closing paren or semicolon
		},
		{
			name: "after_opening_paren",
			input: "CREATE TABLE `t` (\n" +
				"  `id` int NOT NULL\n" +
				") ENGINE=InnoDB;\n" +
				"INSERT INTO `t` VALUES (1);\n" +
				"INSERT INTO `t` VALUES (", // cut immediately after '('
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := Parse(context.Background(), strings.NewReader(tc.input), &out, passthroughApplier{})
			if err != nil {
				t.Fatalf("expected no error on truncated stream, got: %v", err)
			}
			// The complete INSERT before the truncated one must still be present.
			if !strings.Contains(out.String(), "(1,") && !strings.Contains(out.String(), "(1)") {
				t.Fatalf("complete row before truncated INSERT should be in output\ngot: %s", out.String())
			}
		})
	}
}

// TestUnquotedValueReplacementBug verifies a known bug where an unquoted original value
// (like an integer or NULL) replaced by a string value is emitted without quotes,
// resulting in invalid SQL.
func TestUnquotedValueReplacementBug(t *testing.T) {
	input := "CREATE TABLE `t` (\n" +
		"  `id` int NOT NULL,\n" +
		"  `num` int,\n" +
		"  `opt` varchar(100)\n" +
		") ENGINE=InnoDB;\n" +
		"INSERT INTO `t` VALUES (1,999,NULL);\n"

	a := &staticApplier{rules: map[string]map[string]string{
		"t": {
			"num": "Lorem Ipsum",
			"opt": "Replacement String",
		},
	}}

	got := run(t, input, a)

	// Since they are strings, we expect them to be wrapped in single quotes in the output.
	if !strings.Contains(got, "'Lorem Ipsum'") {
		t.Errorf("bug: unquoted integer replacement string is missing quotes.\ngot: %s", got)
	}
	if !strings.Contains(got, "'Replacement String'") {
		t.Errorf("bug: unquoted NULL replacement string is missing quotes.\ngot: %s", got)
	}
}
