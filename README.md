# duckdb-ioc

A native DuckDB loadable extension for **defanging/refanging and extracting indicators of compromise (IOCs) in SQL**: turn threat-intel report text into structured rows of IPs, domains, URLs, e-mails, hashes, and CVEs — and neutralize live indicators so reports are safe to paste.

The matching engine is pure Rust (lazy-compiled regexes, no VGI, no Arrow IPC, no JSON). It is ported verbatim from the MIT-licensed [Query-farm `vgi-ioc`](https://github.com/Query-farm/vgi-ioc) VGI worker; only the Arrow IPC transport layer was replaced with direct DuckDB C-API vector I/O.

## Refang-before-extract

CTI reports almost always *defang* indicators so they can't be accidentally clicked: `http://evil.example.com` is written `hxxp://evil[.]example[.]com`, `1.2.3.4` becomes `1[.]2[.]3[.]4`, `user@evil.com` becomes `user[at]evil[.]com`. A naive extractor run over the raw text would miss every one. So **every extractor and `is_ioc` refangs its input first** (`defang`/`refang` are the only functions that don't — they *are* the fanging step).

## Functions

### Defang / refang
| Function | Signature | Returns |
| --- | --- | --- |
| `defang` | `(text VARCHAR)` | `VARCHAR` | `http`→`hxxp`, `.`→`[.]`, `@`→`[at]`, `://`→`[://]` |
| `refang` | `(text VARCHAR)` | `VARCHAR` | the inverse of `defang` |

### Per-type extractors (all return `VARCHAR[]`)
`extract_ipv4`, `extract_ipv6`, `extract_domains`, `extract_urls`, `extract_emails`, `extract_hashes`, `extract_cves` — each takes `(text VARCHAR)`.

### Classification
| Function | Signature | Returns |
| --- | --- | --- |
| `hash_type` | `(s VARCHAR)` | `VARCHAR` — `md5`/`sha1`/`sha256`/`sha512`, or NULL if not a hash |
| `is_ioc` | `(text VARCHAR)` | `BOOLEAN` |

### One-shot table function
| Function | Signature | Returns |
| --- | --- | --- |
| `extract_iocs` | `(text VARCHAR)` | `table(type VARCHAR, value VARCHAR)` — one row per distinct IOC |

`extract_iocs` takes a **constant** text argument (DuckDB table functions bind positional constants, not row columns). The input is refanged first, results deduplicated, and `type` is one of `{ipv4, ipv6, url, email, domain, md5, sha1, sha256, sha512, cve}`.

### Semantics
- **Overlap:** a bare domain that is already the host of an extracted URL or the domain of an e-mail is **not** also emitted as a standalone domain (URLs/e-mails "win" their hosts).
- **Private/reserved IPs are kept** (`10.0.0.5`, `192.168.x`, …) — they're valid indicators (lateral movement, internal C2).
- **TLD sanity:** a "domain" must end in an alphabetic TLD ≥ 2 chars (reduces matches on `foo.txt`, `app.v2`).
- **Bounded input:** matching is capped at 4 MiB per cell so a pathological cell can't cause unbounded regex work.

## Examples

```sql
-- Neutralize a live indicator so it's safe to paste
SELECT defang('http://evil.com/x');                    -- hxxp[://]evil[.]com/x
SELECT refang('hxxp[://]evil[.]com/x');                -- http://evil.com/x

-- Per-type extractors (refang first, so defanged input still matches)
SELECT extract_ipv4('beacon from 10[.]0[.]0[.]5 and 1.2.3.4');  -- [10.0.0.5, 1.2.3.4]
SELECT extract_domains('visit evil[.]com now');                    -- [evil.com]
SELECT extract_emails('phish mail bad[at]evil[.]com');             -- [bad@evil.com]

-- Classify
SELECT hash_type('d41d8cd98f00b204e9800998ecf8427e');             -- md5
SELECT is_ioc('c2 at 10.0.0.5');                                  -- true

-- One-shot: every distinct IOC as (type, value) rows
SELECT type, value
FROM extract_iocs('beacon to hxxp://evil[.]com from 10[.]0[.]0[.]5 and bad[at]evil[.]com')
ORDER BY type, value;
```

## Build

```bash
make release            # builds libioc.so (cdylib)
# then stamp the loadable-extension metadata footer:
cargo run --bin append_metadata -- \
  target/release/libioc.so target/release/ioc.duckdb_extension \
  --abi-type C_STRUCT --extension-version v0.1.0 --duckdb-version v1.2.0 \
  --platform linux_amd64
```

Load it (unsigned, for local builds):

```sql
LOAD 'target/release/ioc.duckdb_extension';
```

## Tests

`cargo test --release` runs the SQL-level integration suite (10 tests) against a real in-memory DuckDB with the built extension loaded.

## License

MIT — see [LICENSE](LICENSE). The core engine derives from
[Query-farm/vgi-ioc](https://github.com/Query-farm/vgi-ioc) (MIT).
