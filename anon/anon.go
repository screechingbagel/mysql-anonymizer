// Package anon applies per-column anonymization rules to a parsed SQL row.
package anon

import (
	"bytes"
	"fmt"
	"text/template"

	"data-anonymizer/faker"
	"data-anonymizer/mysql"
)

// Anon holds compiled rules for all configured tables.
type Anon struct {
	// rules: table → column → compiled template
	rules map[string]map[string]*template.Template
	// buf is reused across Apply calls (pipeline is single-goroutine).
	buf bytes.Buffer
}

// New creates an Anon from a pre-compiled rules map (as produced by config.Load).
func New(rules map[string]map[string]*template.Template) *Anon {
	return &Anon{rules: rules}
}

// Apply runs anonymization rules against a single row.
//
//   - colNames and cells must have the same length.
//   - cells is modified in-place: each cell's Value is replaced and Quoted is set.
//   - Returns (drop=true, nil) if any rule returns the ::DROP:: sentinel.
//   - Returns (false, err) on template execution error.
//   - If the table or a column has no rule, the original value is kept.
//
// Note: vals entries set to faker.SentinelNULL will be rendered as SQL NULL
// by the parser — this package just sets the sentinel string.
func (a *Anon) Apply(table string, colNames []string, cells []mysql.Cell) (drop bool, err error) {
	tableRules, ok := a.rules[table]
	if !ok {
		return false, nil // no rules for this table — full pass-through
	}

	for i, col := range colNames {
		tpl, ok := tableRules[col]
		if !ok {
			continue // no rule for this column — keep original value
		}

		a.buf.Reset()
		if err := tpl.Execute(&a.buf, nil); err != nil {
			return false, fmt.Errorf("anon: execute rule for %s.%s: %w", table, col, err)
		}

		result := a.buf.String()
		switch result {
		case faker.SentinelDROP:
			return true, nil
		default:
			cells[i].Value = result
			cells[i].Quoted = true
		}
	}
	return false, nil
}
