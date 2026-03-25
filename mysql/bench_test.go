package mysql

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

// generateDump produces a synthetic mysqldump-style INSERT statement with
// numRows rows, each with numCols string columns of the given cell size.
// Returns the full dump bytes and the expected total size.
func generateDump(numRows, numCols, cellSize int) []byte {
	var sb strings.Builder

	// CREATE TABLE
	sb.WriteString("CREATE TABLE `bench` (\n")
	sb.WriteString("  `id` int NOT NULL AUTO_INCREMENT,\n")
	for i := range numCols {
		fmt.Fprintf(&sb, "  `col%d` varchar(255) NOT NULL,\n", i)
	}
	sb.WriteString("  PRIMARY KEY (`id`)\n")
	sb.WriteString(") ENGINE=InnoDB;\n")

	// INSERT INTO `bench` VALUES (row),(row),...;
	cell := strings.Repeat("x", cellSize)
	sb.WriteString("INSERT INTO `bench` VALUES ")
	for r := range numRows {
		if r > 0 {
			sb.WriteString(",\n")
		}
		sb.WriteByte('(')
		fmt.Fprintf(&sb, "%d", r+1) // id
		for range numCols {
			sb.WriteString(",'")
			sb.WriteString(cell)
			sb.WriteByte('\'')
		}
		sb.WriteByte(')')
	}
	sb.WriteString(";\n")

	return []byte(sb.String())
}

// BenchmarkParserThroughput measures raw parse+passthrough throughput.
// No anonymization rules applied — this is the ceiling: how fast can we
// read and copy a mysqldump with zero transformations.
func BenchmarkParserPassthrough(b *testing.B) {
	for _, tc := range []struct {
		rows, cols, cellSize int
	}{
		{1_000, 10, 32},
		{10_000, 10, 32},
		{1_000, 10, 256},
	} {
		name := fmt.Sprintf("rows=%d/cols=%d/cell=%d", tc.rows, tc.cols, tc.cellSize)
		dump := generateDump(tc.rows, tc.cols, tc.cellSize)
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(dump)))
			b.ResetTimer()
			for b.Loop() {
				r := bytes.NewReader(dump)
				if err := Parse(r, io.Discard, passthroughApplier{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkParserWithRules measures throughput when every column has a
// static replacement rule — the hot path through anon.Apply + template.Execute.
func BenchmarkParserWithRules(b *testing.B) {
	for _, tc := range []struct {
		rows, cols, cellSize int
	}{
		{1_000, 10, 32},
		{10_000, 10, 32},
	} {
		name := fmt.Sprintf("rows=%d/cols=%d/cell=%d", tc.rows, tc.cols, tc.cellSize)
		dump := generateDump(tc.rows, tc.cols, tc.cellSize)

		// Build column rules: replace every col with a static string.
		colRules := make(map[string]string, tc.cols)
		colNames := make([]string, tc.cols)
		for i := range tc.cols {
			k := fmt.Sprintf("col%d", i)
			colRules[k] = "REPLACED"
			colNames[i] = k
		}
		a := &staticApplier{rules: map[string]map[string]string{"bench": colRules}}

		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(dump)))
			b.ResetTimer()
			for b.Loop() {
				r := bytes.NewReader(dump)
				if err := Parse(r, io.Discard, a); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkParseRow isolates the inner cell-parsing loop from I/O.
// Measures how fast we can parse a single row of cells.
func BenchmarkParseRow(b *testing.B) {
	// Simulate the payload for one row: 10 string cells of 32 bytes each.
	cells := make([]string, 10)
	for i := range cells {
		cells[i] = fmt.Sprintf("'%s'", strings.Repeat("x", 32))
	}
	rowPayload := []byte("(" + strings.Join(cells, ",") + ")")

	p := &parser{
		cellBuf: make([]byte, 0, 256),
		valsBuf: make([]string, 0, 16),
	}

	b.SetBytes(int64(len(rowPayload)))
	b.ResetTimer()
	for b.Loop() {
		p.parseRow(rowPayload, 1) //nolint:errcheck
	}
}
