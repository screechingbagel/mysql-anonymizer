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
// On read: mysqldump encodes a literal single-quote inside a string cell as
// either \' (backslash-quote) or '' (doubled-quote). The parser decodes both
// forms to the raw character before handing the value to the Applier.
//
// On write: when emitting a (potentially transformed) string cell the parser
// re-encodes using MySQL's standard backslash escaping:
//
//	\  → \\
//	'  → \'
//
// This matches the format mysqldump itself produces and is accepted by all
// MySQL-compatible servers. Note that the doubled-quote form ('') is never
// emitted on output — only the backslash form is used.
package mysql

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"unsafe"

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
func Parse(ctx context.Context, r io.Reader, w io.Writer, a Applier) error {
	br := bufio.NewReaderSize(r, readBufSize)
	bw := bufio.NewWriterSize(w, writeBufSize)

	p := &parser{
		ctx: ctx,
		br:  br,
		bw:  bw,
		a:   a,
	}
	if err := p.run(); err != nil {
		// Flush even on cancellation so partial output is written.
		_ = bw.Flush()
		return err
	}
	return bw.Flush()
}

// ─── Internal parser state ────────────────────────────────────────────────────

type parser struct {
	ctx context.Context
	br  *bufio.Reader
	bw  *bufio.Writer
	a   Applier

	// Known tables: table name → ordered column names.
	// Populated from CREATE TABLE statements.
	tables map[string][]string

	// Scratch buffers reused across rows to reduce allocations.
	cellBuf    []byte // raw bytes of a single cell
	valsBuf    []string
	payloadBuf []byte // accumulated INSERT payload, reset per statement
	quotedBuf  []bool // parallel wasQuoted flags, reset per row
	binaryBuf  []bool // parallel wasBinary flags (_binary '...'), reset per row
}

func (p *parser) run() error {
	p.tables = make(map[string][]string, 32)
	p.cellBuf = make([]byte, 0, 256)
	p.valsBuf = make([]string, 0, 64)
	p.payloadBuf = make([]byte, 0, 4*1024)
	p.quotedBuf = make([]bool, 0, 64)
	p.binaryBuf = make([]bool, 0, 64)

	for {
		if err := p.ctx.Err(); err != nil {
			return err
		}
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
		// Use ReadSlice instead of ReadBytes to avoid per-line heap
		// allocations. ReadSlice returns a view into the reader's internal
		// buffer — zero copies for typical DDL lines. Falls back to manual
		// collection only when a line exceeds the buffer (very rare for DDL).
		line, err := p.br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			// Line exceeds buffer — collect the full line.
			full := make([]byte, len(line))
			copy(full, line)
			for err == bufio.ErrBufferFull {
				var rest []byte
				rest, err = p.br.ReadSlice('\n')
				full = append(full, rest...)
			}
			if err != nil && err != io.EOF {
				return fmt.Errorf("mysql parser: CREATE TABLE read: %w", err)
			}
			line = full
		} else if err == io.EOF && len(line) == 0 {
			break
		} else if err != nil && err != io.EOF {
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
		// Use ReadSlice to avoid per-line allocation. The returned slice
		// is only valid until the next read, but the append below copies
		// the data into payloadBuf immediately.
		nextLine, err := p.br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			// Line exceeds buffer — append what we have and keep reading.
			p.payloadBuf = append(p.payloadBuf, nextLine...)
			for err == bufio.ErrBufferFull {
				nextLine, err = p.br.ReadSlice('\n')
				p.payloadBuf = append(p.payloadBuf, nextLine...)
			}
		} else {
			p.payloadBuf = append(p.payloadBuf, nextLine...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("mysql parser: INSERT read: %w", err)
		}
	}
	payload := p.payloadBuf

	// Find "VALUES" in payload to locate row start position.
	valStart := bytes.Index(payload, []byte("VALUES"))
	if valStart < 0 {
		// Not a VALUES insert (unlikely with mysqldump, but be safe).
		// Write: INSERT INTO `tablename`
		for _, s := range []string{"INSERT INTO `", tableName, "`"} {
			if _, err := p.bw.WriteString(s); err != nil {
				return err
			}
		}
		_, err := p.bw.Write(payload)
		return err
	}

	// columnList is everything between the closing backtick of the table name
	// and the VALUES keyword — e.g. " (`id`,`name`,`country`) ".
	// mysqldump always emits this when --complete-insert is used, and some
	// versions emit it by default. We must preserve it verbatim so that the
	// output remains safe to re-import even if the schema later gains columns.
	columnList := bytes.TrimSpace(payload[:valStart])

	// Write: INSERT INTO `tablename` [columnList ]VALUES
	if _, err := p.bw.WriteString("INSERT INTO `"); err != nil {
		return err
	}
	if _, err := p.bw.WriteString(tableName); err != nil {
		return err
	}
	if err := p.bw.WriteByte('`'); err != nil {
		return err
	}
	if len(columnList) > 0 {
		if err := p.bw.WriteByte(' '); err != nil {
			return err
		}
		if _, err := p.bw.Write(columnList); err != nil {
			return err
		}
	}
	if _, err := p.bw.WriteString(" VALUES"); err != nil {
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
		if err := p.ctx.Err(); err != nil {
			return err
		}
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
			vals, wasQuoted, wasBinary, newPos, err := p.parseRow(payload, pos)
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
			if err := p.writeRow(vals, wasQuoted, wasBinary); err != nil {
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
//
// Hot-path allocation strategy:
//
//	For cells with no backslash or doubled-quote escapes (the vast majority of
//	mysqldump output), we take a direct unsafe.String view of the payload
//	slice — zero copies, zero allocations. The cellBuf copy path is only
//	triggered when escape decoding is required.
func (p *parser) parseRow(payload []byte, pos int) (vals []string, wasQuoted []bool, wasBinary []bool, newPos int, err error) {
	p.valsBuf = p.valsBuf[:0]
	p.quotedBuf = p.quotedBuf[:0]
	p.binaryBuf = p.binaryBuf[:0]

	for pos < len(payload) {
		ch := payload[pos]

		if ch == ')' {
			pos++ // consume ')'
			return p.valsBuf, p.quotedBuf, p.binaryBuf, pos, nil
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
			start := pos
			escaped := false

			// First pass: scan for unescaped close-quote.
			for pos < len(payload) {
				c := payload[pos]
				if c == '\\' && pos+1 < len(payload) {
					escaped = true
					pos += 2
					continue
				}
				if c == '\'' {
					if pos+1 < len(payload) && payload[pos+1] == '\'' {
						escaped = true
						pos += 2
						continue
					}
					// End of string.
					break
				}
				pos++
			}

			if !escaped {
				// Fast path: no escape sequences — reference payload directly.
				p.valsBuf = append(p.valsBuf, unsafe.String(&payload[start], pos-start))
			} else {
				// Slow path: decode escapes into cellBuf.
				p.cellBuf = p.cellBuf[:0]
				for i := start; i < pos; {
					c := payload[i]
					if c == '\\' && i+1 < pos {
						p.cellBuf = append(p.cellBuf, payload[i+1])
						i += 2
						continue
					}
					if c == '\'' && i+1 < pos && payload[i+1] == '\'' {
						p.cellBuf = append(p.cellBuf, '\'')
						i += 2
						continue
					}
					p.cellBuf = append(p.cellBuf, c)
					i++
				}
				p.valsBuf = append(p.valsBuf, string(p.cellBuf))
			}
			if pos < len(payload) {
				pos++ // consume closing '
			}
			p.quotedBuf = append(p.quotedBuf, true)
			p.binaryBuf = append(p.binaryBuf, false)
			continue
		}

		// Binary string: _binary '...'
		if bytes.HasPrefix(payload[pos:], []byte("_binary '")) {
			pos += len("_binary '")
			start := pos
			escaped := false

			for pos < len(payload) {
				c := payload[pos]
				if c == '\\' && pos+1 < len(payload) {
					escaped = true
					pos += 2
					continue
				}
				if c == '\'' {
					if pos+1 < len(payload) && payload[pos+1] == '\'' {
						escaped = true
						pos += 2
						continue
					}
					break
				}
				pos++
			}

			if !escaped {
				p.valsBuf = append(p.valsBuf, unsafe.String(&payload[start], pos-start))
			} else {
				p.cellBuf = p.cellBuf[:0]
				for i := start; i < pos; {
					c := payload[i]
					if c == '\\' && i+1 < pos {
						p.cellBuf = append(p.cellBuf, payload[i+1])
						i += 2
						continue
					}
					if c == '\'' && i+1 < pos && payload[i+1] == '\'' {
						p.cellBuf = append(p.cellBuf, '\'')
						i += 2
						continue
					}
					p.cellBuf = append(p.cellBuf, c)
					i++
				}
				p.valsBuf = append(p.valsBuf, string(p.cellBuf))
			}
			if pos < len(payload) {
				pos++ // consume closing '
			}
			p.quotedBuf = append(p.quotedBuf, true)
			p.binaryBuf = append(p.binaryBuf, true) // preserve _binary prefix on output
			continue
		}

		// Bare cell: NULL, numeric, bit literal, hex literal, etc.
		// Read until next ',' or ')'.
		start := pos
		for pos < len(payload) {
			c := payload[pos]
			if c == ',' || c == ')' || c == '\r' || c == '\n' {
				break
			}
			pos++
		}
		// Trim trailing spaces inline to avoid bytes.TrimSpace allocation.
		end := pos
		for end > start && payload[end-1] == ' ' {
			end--
		}
		p.valsBuf = append(p.valsBuf, unsafe.String(&payload[start], end-start))
		p.quotedBuf = append(p.quotedBuf, false)
		p.binaryBuf = append(p.binaryBuf, false)
	}

	return p.valsBuf, p.quotedBuf, p.binaryBuf, pos, fmt.Errorf("mysql parser: unterminated row in payload")
}

// writeRow writes one transformed row as "(val1,val2,...)" to bw.
// wasBinary[i] true means the original cell had a _binary '...' prefix which
// must be re-emitted so MySQL correctly handles binary column values.
func (p *parser) writeRow(vals []string, wasQuoted []bool, wasBinary []bool) error {
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
			// Re-emit _binary prefix if present in the original.
			if i < len(wasBinary) && wasBinary[i] {
				if _, err := p.bw.WriteString("_binary "); err != nil {
					return err
				}
			}
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

// writeSQLEscaped writes s to w using MySQL's standard backslash-escape
// conventions for string literals:
//
//	\  → \\
//	'  → \'
//
// Any other characters — including NUL bytes and non-ASCII sequences — are
// written verbatim. Safe (non-escaping) runs are written in a single call to
// minimise system-call overhead on the hot path.
func writeSQLEscaped(w *bufio.Writer, s string) error {
	// Scan for the first byte that needs escaping using a simple loop.
	// This replaces strings.IndexAny which rebuilds a 256-bit ASCII set
	// on every call — a significant cost on the hot path.
	for len(s) > 0 {
		i := indexEscapeByte(s)
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

// indexEscapeByte returns the index of the first byte in s that needs SQL
// escaping ('\' or '\''), or -1 if none. This is a hot-path replacement
// for strings.IndexAny(s, `\\'`) that avoids the per-call ASCII-set
// construction overhead.
func indexEscapeByte(s string) int {
	for i := range len(s) {
		if s[i] == '\\' || s[i] == '\'' {
			return i
		}
	}
	return -1
}
