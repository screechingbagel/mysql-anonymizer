// Package mysql implements a streaming parser for mysqldump output.
//
// It reads from an io.Reader, applies anonymization rules via the provided
// Applier, and writes to an io.Writer. Lines that don't belong to a CREATE
// TABLE or INSERT INTO statement are passed through verbatim.
//
// # Parser overview
//
// The input is read with a large bufio.Reader. The state machine advances
// one line at a time for "outer" states, and byte-by-byte for the row-values
// region inside an INSERT INTO statement.
//
// States:
//
//	passthrough      – copy every line verbatim; scan for CREATE/INSERT keywords
//	createTable      – collect ordered column names from CREATE TABLE body
//	insertHeader     – extract table name from INSERT INTO `...`
//	rowValues        – parse and transform VALUES (cell, cell,...),(cell,...);
//
// # Cell quoting
//
// mysqldump quotes string cells in single quotes ('...') and leaves numeric
// and NULL cells bare. When we write a transformed cell, we use the same
// quoting style as the original cell — not the column's DDL type. This
// avoids having to parse column type declarations at all.
//
//   - If the original cell was inside single quotes  → wrap output in '...'
//     and escape any backslashes and single quotes in the output value.
//   - If original cell was bare (NULL, numeric)       → write value verbatim;
//     unless the rule produced ::NULL::, in which case write NULL.
//
// # Escape sequences in string cells
//
// mysqldump escapes single-quote as \' (backslash-quote) and also as ”
// (doubled quote). Both are correctly handled during reading. On output,
// substituted values have ' escaped to \' and \ escaped to \\.
package mysql

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"data-anonymizer/faker"
)

// Applier is implemented by anon.Anon.
type Applier interface {
	// Apply transforms vals in-place for the given table.
	// Returns drop=true if the row should be omitted from output.
	Apply(table string, colNames []string, vals []string) (drop bool, err error)
}

// ─── Parser ───────────────────────────────────────────────────────────────────

const (
	readBufSize  = 64 * 1024 // 64 KiB read buffer
	writeBufSize = 64 * 1024 // 64 KiB write buffer
)

// Parse reads a mysqldump stream from r, applies rules via a, and writes
// the (possibly transformed) dump to w.
func Parse(r io.Reader, w io.Writer, a Applier) error {
	br := bufio.NewReaderSize(r, readBufSize)
	bw := bufio.NewWriterSize(w, writeBufSize)

	p := &parser{
		br: br,
		bw: bw,
		a:  a,
	}
	if err := p.run(); err != nil {
		return err
	}
	return bw.Flush()
}

// ─── Internal parser state ────────────────────────────────────────────────────

type parser struct {
	br *bufio.Reader
	bw *bufio.Writer
	a  Applier

	// Known tables: table name → ordered column names.
	// Populated from CREATE TABLE statements.
	tables map[string][]string

	// Scratch buffers reused across rows to reduce allocations.
	cellBuf    []byte   // raw bytes of a single cell
	valsBuf    []string
	payloadBuf []byte   // accumulated INSERT payload, reset per statement
	quotedBuf  []bool   // parallel wasQuoted flags, reset per row
}

func (p *parser) run() error {
	p.tables = make(map[string][]string, 32)
	p.cellBuf = make([]byte, 0, 256)
	p.valsBuf = make([]string, 0, 64)
	p.payloadBuf = make([]byte, 0, 4*1024)
	p.quotedBuf = make([]bool, 0, 64)

	for {
		line, err := p.br.ReadSlice('\n')
		if err == io.EOF {
			// Flush any remaining bytes (file may not end with newline).
			if len(line) > 0 {
				if werr := p.dispatchLine(line); werr != nil {
					return werr
				}
			}
			return nil
		}
		if err == bufio.ErrBufferFull {
			// Line is longer than buffer — rare in DDL, common in large VALUE blocks.
			// Collect the full line.
			full := make([]byte, len(line))
			copy(full, line)
			for err == bufio.ErrBufferFull {
				var rest []byte
				rest, err = p.br.ReadSlice('\n')
				full = append(full, rest...)
			}
			if err != nil && err != io.EOF {
				return fmt.Errorf("mysql parser: read: %w", err)
			}
			line = full
		} else if err != nil {
			return fmt.Errorf("mysql parser: read: %w", err)
		}

		if err := p.dispatchLine(line); err != nil {
			return err
		}
	}
}

// dispatchLine decides how to handle a line depending on its content.
func (p *parser) dispatchLine(line []byte) error {
	// Fast check: CREATE TABLE `name` (
	if bytes.HasPrefix(line, []byte("CREATE TABLE `")) {
		return p.parseCreateTable(line)
	}

	// INSERT INTO `name` VALUES ...
	if bytes.HasPrefix(line, []byte("INSERT INTO `")) {
		return p.parseInsertLine(line)
	}

	// Everything else: pass through verbatim.
	_, err := p.bw.Write(line)
	return err
}

// ─── CREATE TABLE parsing ─────────────────────────────────────────────────────

// parseCreateTable reads from the current line onwards until the closing ");"
// and collects column names in declaration order.
//
// The CREATE TABLE line itself is passed through. Each column definition line
// is also passed through. We only extract the column name, not the type.
func (p *parser) parseCreateTable(firstLine []byte) error {
	// Extract table name from: CREATE TABLE `name` (
	name, ok := extractBacktickName(firstLine)
	if !ok {
		// Can't parse; pass through and ignore.
		_, err := p.bw.Write(firstLine)
		return err
	}

	// Write the CREATE TABLE line verbatim.
	if _, err := p.bw.Write(firstLine); err != nil {
		return err
	}

	var cols []string

	for {
		line, err := p.br.ReadBytes('\n')
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err != nil && err != io.EOF {
			return fmt.Errorf("mysql parser: CREATE TABLE read: %w", err)
		}

		// Pass through verbatim.
		if _, werr := p.bw.Write(line); werr != nil {
			return werr
		}

		trimmed := bytes.TrimSpace(line)

		// End of CREATE TABLE block.
		if bytes.HasPrefix(trimmed, []byte(")")) {
			break
		}

		// Skip constraint/index lines that start with a keyword rather than a backtick.
		// e.g.: PRIMARY KEY, KEY, UNIQUE KEY, CONSTRAINT, FOREIGN KEY
		if len(trimmed) > 0 && trimmed[0] != '`' {
			continue
		}

		// Column definition: starts with `colname`
		if colName, ok := extractBacktickName(trimmed); ok {
			cols = append(cols, colName)
		}
	}

	p.tables[name] = cols
	return nil
}

// ─── INSERT INTO parsing ──────────────────────────────────────────────────────

// parseInsertLine handles one INSERT INTO statement.
// INSERT INTO may span multiple lines (each VALUES row on its own line).
//
// Format mysqldump uses:
//
//	INSERT INTO `table` VALUES (row),(row),(row);
//
// or multi-line:
//
//	INSERT INTO `table` VALUES (row),
//	(row),
//	(row);
func (p *parser) parseInsertLine(line []byte) error {
	// Extract table name.
	// Line: INSERT INTO `tablename` VALUES ...
	after := line[len("INSERT INTO `"):]
	before, after0, ok := bytes.Cut(after, []byte{'`'})
	if !ok {
		// Malformed; pass through.
		_, err := p.bw.Write(line)
		return err
	}
	tableName := string(before)
	colNames := p.tables[tableName] // may be nil (no CREATE TABLE seen)

	// Find the VALUES keyword and collect the entire rest of the statement.
	// We need to handle the case where VALUES rows continue on subsequent lines.

	// remainder starts after the table name backtick.
	// We need to find "VALUES" then the opening "(" of the first row.
	rest := after0

	// Accumulate the full VALUES payload (may span multiple lines) into a
	// reused scratch buffer to avoid a per-statement heap allocation.
	p.payloadBuf = append(p.payloadBuf[:0], rest...)

	for !statementTerminated(p.payloadBuf) {
		nextLine, err := p.br.ReadBytes('\n')
		p.payloadBuf = append(p.payloadBuf, nextLine...)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("mysql parser: INSERT read: %w", err)
		}
	}
	payload := p.payloadBuf

	// Write: INSERT INTO `tablename` VALUES
	for _, s := range []string{"INSERT INTO `", tableName, "` VALUES"} {
		if _, err := p.bw.WriteString(s); err != nil {
			return err
		}
	}

	// Find "VALUES" in payload to locate row start position.
	valStart := bytes.Index(payload, []byte("VALUES"))
	if valStart < 0 {
		// Not a VALUES insert (unlikely with mysqldump, but be safe).
		_, err := p.bw.Write(payload)
		return err
	}

	return p.writeRows(tableName, colNames, payload, valStart+len("VALUES"))
}

// statementTerminated reports whether the INSERT payload ends with ";".
// We need to handle the trailing "\n" that follows on mysqldump output.
func statementTerminated(b []byte) bool {
	t := bytes.TrimRight(b, " \t\r\n")
	return len(t) > 0 && t[len(t)-1] == ';'
}

// writeRows iterates over the row tuples in payload starting at pos and
// writes the (possibly transformed) output to bw.
func (p *parser) writeRows(tableName string, colNames []string, payload []byte, pos int) error {
	first := true

	for pos < len(payload) {
		ch := payload[pos]

		if ch == ';' {
			// End of statement.
			if _, err := p.bw.WriteString(";\n"); err != nil {
				return err
			}
			return nil
		}

		if ch == ',' || ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
			pos++
			continue
		}

		if ch == '(' {
			pos++ // consume '('

			// Parse one row.
			vals, wasQuoted, newPos, err := p.parseRow(payload, pos)
			if err != nil {
				return err
			}
			pos = newPos

			// Apply anonymization rules.
			drop, err := p.a.Apply(tableName, colNames, vals)
			if err != nil {
				return fmt.Errorf("mysql parser: apply rules for %s: %w", tableName, err)
			}

			if drop {
				// Skip this row.
				continue
			}

			// Write separator between rows.
			if !first {
				if _, err := p.bw.WriteString(",\n"); err != nil {
					return err
				}
			}
			first = false

			// Write transformed row.
			if err := p.writeRow(vals, wasQuoted); err != nil {
				return err
			}

			continue
		}

		// Unexpected character — advance past it (defensive).
		pos++
	}

	return nil
}

// parseRow parses the cell values of one tuple starting at pos (after the
// opening '(' has been consumed). Returns the cell values, a parallel bool
// slice indicating which cells were originally single-quoted, and the new
// position in payload (pointing just after the closing ')').
func (p *parser) parseRow(payload []byte, pos int) (vals []string, wasQuoted []bool, newPos int, err error) {
	p.valsBuf = p.valsBuf[:0]
	p.quotedBuf = p.quotedBuf[:0]

	for pos < len(payload) {
		ch := payload[pos]

		if ch == ')' {
			pos++ // consume ')'
			return p.valsBuf, p.quotedBuf, pos, nil
		}

		if ch == ',' {
			pos++ // separator between cells
			continue
		}

		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
			pos++
			continue
		}

		// String cell: starts with '
		if ch == '\'' {
			pos++ // consume opening '
			p.cellBuf = p.cellBuf[:0]

			for pos < len(payload) {
				c := payload[pos]
				if c == '\\' && pos+1 < len(payload) {
					// Backslash escape: decode to actual character.
					p.cellBuf = append(p.cellBuf, payload[pos+1])
					pos += 2
					continue
				}
				if c == '\'' {
					// Could be '' (escaped quote) or end of string.
					if pos+1 < len(payload) && payload[pos+1] == '\'' {
						// '' → single '
						p.cellBuf = append(p.cellBuf, '\'')
						pos += 2
						continue
					}
					// End of string.
					pos++ // consume closing '
					break
				}
				p.cellBuf = append(p.cellBuf, c)
				pos++
			}

			p.valsBuf = append(p.valsBuf, string(p.cellBuf))
			p.quotedBuf = append(p.quotedBuf, true)
			continue
		}

		// Binary string: _binary '...'
		if bytes.HasPrefix(payload[pos:], []byte("_binary '")) {
			pos += len("_binary '")
			p.cellBuf = p.cellBuf[:0]

			for pos < len(payload) {
				c := payload[pos]
				if c == '\\' && pos+1 < len(payload) {
					p.cellBuf = append(p.cellBuf, payload[pos+1])
					pos += 2
					continue
				}
				if c == '\'' {
					if pos+1 < len(payload) && payload[pos+1] == '\'' {
						p.cellBuf = append(p.cellBuf, '\'')
						pos += 2
						continue
					}
					pos++ // consume closing '
					break
				}
				p.cellBuf = append(p.cellBuf, c)
				pos++
			}
			p.valsBuf = append(p.valsBuf, string(p.cellBuf))
			p.quotedBuf = append(p.quotedBuf, true)
			continue
		}

		// Bare cell: NULL, numeric, bit literal, hex literal, etc.
		// Read until next ',' or ')'.
		p.cellBuf = p.cellBuf[:0]
		for pos < len(payload) {
			c := payload[pos]
			if c == ',' || c == ')' || c == '\r' || c == '\n' {
				break
			}
			p.cellBuf = append(p.cellBuf, c)
			pos++
		}
		p.valsBuf = append(p.valsBuf, string(bytes.TrimSpace(p.cellBuf)))
		p.quotedBuf = append(p.quotedBuf, false)
	}

	return p.valsBuf, p.quotedBuf, pos, fmt.Errorf("mysql parser: unterminated row in payload")
}

// writeRow writes one transformed row as "(val1,val2,...)" to bw.
func (p *parser) writeRow(vals []string, wasQuoted []bool) error {
	if err := p.bw.WriteByte('('); err != nil {
		return err
	}

	for i, v := range vals {
		if i > 0 {
			if err := p.bw.WriteByte(','); err != nil {
				return err
			}
		}

		if v == faker.SentinelNULL {
			if _, err := p.bw.WriteString("NULL"); err != nil {
				return err
			}
			continue
		}

		if wasQuoted[i] {
			// Escape the value and wrap in single quotes.
			if err := p.bw.WriteByte('\''); err != nil {
				return err
			}
			if err := writeSQLEscaped(p.bw, v); err != nil {
				return err
			}
			if err := p.bw.WriteByte('\''); err != nil {
				return err
			}
		} else {
			// Bare value (numeric, NULL was handled above).
			if _, err := p.bw.WriteString(v); err != nil {
				return err
			}
		}
	}

	return p.bw.WriteByte(')')
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// extractBacktickName extracts the identifier between the first pair of
// backticks in b. Returns ("", false) if none found.
func extractBacktickName(b []byte) (string, bool) {
	_, mid, ok := bytes.Cut(b, []byte{'`'})
	if !ok {
		return "", false
	}
	name, _, ok := bytes.Cut(mid, []byte{'`'})
	if !ok {
		return "", false
	}
	return string(name), true
}

// writeSQLEscaped writes s to w, escaping backslashes and single quotes
// using MySQL's standard escape conventions (\ → \\, ' → \').
// Unescaped segments are written in bulk to minimise write calls.
func writeSQLEscaped(w *bufio.Writer, s string) error {
	const needsEscape = `\'`

	// Fast path: nothing to escape.
	if !strings.ContainsAny(s, needsEscape) {
		_, err := w.WriteString(s)
		return err
	}

	// Write runs of safe characters in bulk, one WriteString per run.
	for len(s) > 0 {
		i := strings.IndexAny(s, needsEscape)
		if i < 0 {
			// Remainder has nothing to escape.
			_, err := w.WriteString(s)
			return err
		}
		// Write the safe prefix.
		if i > 0 {
			if _, err := w.WriteString(s[:i]); err != nil {
				return err
			}
		}
		// Escape the triggering character.
		if err := w.WriteByte('\\'); err != nil {
			return err
		}
		if err := w.WriteByte(s[i]); err != nil {
			return err
		}
		s = s[i+1:]
	}
	return nil
}
