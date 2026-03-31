# data-anonymizer

Reads a MySQL dump on stdin, replaces configured column values, and writes the result to stdout. Designed to sit in a `mysqldump | anonymizer | mysql` pipeline.

## Usage

```bash
mysqldump --single-transaction mydb \
  | data-anonymizer -c config.yaml \
  | mysql stagingdb
```

**Profiling with both CPU and Memory enabled:**

```bash
mysqldump ... | data-anonymizer -c config.yaml --cpuprofile cpu.pprof --memprofile mem.pprof | mysql ...
```

**Flags**

| Flag | Default | Description |
|---|---|---|
| `-c` | `/data-anonymizer.conf` | Config file path |
| `-i` | stdin | Read from file instead |
| `-o` | stdout | Write to file instead |
| `--cpuprofile` | | Write CPU profile to path |
| `--memprofile` | | Write heap profile to path |

## Config

```yaml
progress:
  rhythm: 30s       # how often to print throughput to stderr; omit to disable
  humanize: true    # print sizes as "12 MiB" instead of raw bytes

filters:
  table_name:
    columns:
      column_name:
        value: "{{ fakerEmail }}"   # Go template; result replaces the cell value
```

Every `value` is a [Go template](https://pkg.go.dev/text/template). It is compiled once at startup — if any template is invalid the process exits immediately with an error.

Lines that don't match a configured table/column are passed through unchanged. `CREATE TABLE` statements are always passed through unchanged (they're only read to learn column order).

## Template functions

### Generators

| Function | Example output |
|---|---|
| `fakerName` | `Alice Smith` |
| `fakerFirstName` | `Alice` |
| `fakerLastName` | `Smith` |
| `fakerEmail` | `alice@example.com` |
| `fakerPhone` | `6051234567` |
| `fakerAddress` | `123 Main St, Springfield, IL 62701` |
| `fakerStreetAddress` | `123 Main St` |
| `fakerSecondaryAddress` | `Apt. 042` |
| `fakerCity` | `Springfield` |
| `fakerPostcode` | `62701` |
| `fakerCompany` | `Acme Corp` |
| `fakerIBAN` | `AB12345678901234567890` |
| `fakerSwift` | `ABCDEF12` |
| `fakerEIN` | `12-3456789` |
| `fakerInvoice` | `INV-00000001` (sequential, in-memory counter, resets on restart) |
| `uuidv4` | `550e8400-e29b-41d4-a716-446655440000` |
| `randAlphaNum N` | random `[a-zA-Z0-9]` string of length N |
| `randNumeric N` | random digit string of length N |

### Sentinels

| Function | Effect |
|---|---|
| `{{ null }}` | Writes a bare SQL `NULL`. **Must be the exact and only output** of the template (e.g. `value: "{{ null }}"`). |
| `{{ drop }}` | Omits the entire row from output. **Must be the exact and only output** of the template. |

### Utilities

| Function | Description |
|---|---|
| `upper` | `{{ randAlphaNum 8 \| upper }}` |
| `lower` | `{{ fakerName \| lower }}` |

Go's built-in template functions (`print`, `printf`, `index`, etc.) are also available.

## Example rules

```yaml
filters:
  users:
    columns:
      email:
        value: "{{ fakerEmail }}"
      password_hash:
        value: "$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi"  # static
      api_token:
        value: "{{ uuidv4 }}"
      deleted_at:
        value: "{{ null }}"
      notes:
        value: "Team_{{ randAlphaNum 8 | upper }}"

  audit_log:
    columns:
      ip_address:
        value: "127.0.0.1"
```

## Output format

All lines outside `INSERT INTO` statements — DDL, comments, `LOCK TABLES`, etc. — are passed through byte-for-byte.

`INSERT INTO` statements are reconstructed cell-by-cell:

- **Column list preserved.** If the original statement used the named-column form (`INSERT INTO \`t\` (\`a\`,\`b\`) VALUES …`), the column list is re-emitted verbatim. This is the safe form for re-import when the schema may later gain columns.
- **Quoting style preserved for untouched cells.** Cells passed through without modification retain their original quoting: bare cells (numbers, `NULL`) are written bare, and single-quoted cells remain single-quoted. However, **all substituted values** (except `{{ null }}`) are unconditionally written as single-quoted strings. This relies on MySQL's implicit type coercion for numeric columns.
- **String escaping.** Substituted string values are re-encoded using MySQL's backslash-escape convention:

  | Character | Encoded as |
  |-----------|------------|
  | `\`       | `\\`       |
  | `'`       | `\'`       |

  All other characters (including non-ASCII and NUL bytes) are written verbatim. The doubled-quote form (`''`) used by some MySQL clients on input is **never** produced on output — only the backslash form is used.

## Building

```bash
go build -o data-anonymizer .
```
