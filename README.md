# Honeypot Analyzer 1.0

An offline, deterministic Python analyzer for Cowrie JSONL and the structured logs in T-Pot exports. No AI, API keys, internet access, or third-party Python packages are required. Python 3.10 or newer is required. Runs on Windows, Linux, and macOS.

## Quick start


```powershell
py -3 .\analyze.py "$env:USERPROFILE\Desktop\t-pot" --out report-01
Start-Process .\report-01\report.html
```

Or pass an archive directly (it is read without extracting files):

```powershell
py -3 .\analyze.py "C:\Logs\t-pot.zip" "C:\Logs\cowrie.json" --out report-02
```

Linux/Kali:

```bash
python3 analyze.py /path/to/logs --out report-01
```

Use a new output directory each time. Existing reports are never overwritten. Keep output directories outside input directories to avoid reingesting exports on later runs.

## Filtering and redaction

```powershell
py -3 .\analyze.py "C:\Logs\t-pot.zip" --out report-filtered --exclude-ip [IP ADDR] --first-hours 24 --redact YOUR_HONEYPOT_IP --redact YOUR_HOSTNAME
```

Replace placeholders with real values. Each `--exclude-ip` accepts an IP or CIDR and can be repeated. Exclusion removes records whose normalized source IP matches. It does not remove that IP if it appears as text in some other record; use `--redact` as well if needed. `--redact` performs literal, case-sensitive replacement throughout generated output, including filenames in evidence references. Redaction is explicit, not automatic discovery of sensitive information. Review before sharing: reports can contain usernames, attempted passwords, IPs, commands, and URL parameters.

`--first-hours 24` starts at the earliest timestamped honeypot event remaining after source exclusions and any explicit time bounds. It does not imply 24 hours were actually observed. End boundaries are exclusive. With several sensors, the earliest eligible sensor determines the shared window.

```powershell
py -3 .\analyze.py "C:\Logs" --out report-window --start 2026-10-28T00:00:00Z --end 2026-10-29T00:00:00Z
```

All report times are UTC. Timestamps without offsets are assumed UTC. Untimed records appear in unfiltered runs but are dropped when a time filter is set.

## Outputs

* `report.html`: standalone report with tables and volume bars. Open locally; use browser Print → Save as PDF if desired.
* `summary.json`: counts, observed bounds, categories, and filter accounting.
* `events.jsonl` and `events.csv`: normalized evidence, sensor, session, source file, and line number. JSONL preserves exact strings after requested redactions; CSV prefixes spreadsheet-formula-like values with an apostrophe.
* `source_ips.csv`: ranked sources with optional offline enrichment.
* `commands.csv`, `http_paths.csv`, `usernames.csv`, `passwords.csv`: complete distinct nonempty values with counts.
* `services.csv`, `ports.csv`, `event_types.csv`, `hourly.csv`: event-based activity breakdowns.
* `rule_matches.csv`: matching rules and evidence references. Honeytrap decoded-payload matches may have an empty command/URI; inspect the referenced original record.
* `coverage.json`: files considered, SHA-256 of decompressed bytes actually read, JSON/non-JSON line counts, unsupported records, and errors. A hash is not a full-file hash when reading stops at a configured limit.

## Supported formats and limitations

Supported inputs are directories, ZIPs, and newline-delimited JSON files named `.json`, `.jsonl`, `.ndjson`, or `.log`, including numeric rotations and `.gz` compression. Each nonblank line must contain one JSON object. Pretty-printed JSON arrays, Elasticsearch bulk response envelopes, CSV, PCAP, and text-only logs are not supported. Individual Elasticsearch `_source` objects on single lines can be unwrapped, but only recognized field names are normalized.

Verified against the supplied Cowrie export and T-Pot export: Cowrie `eventid` records, T-Pot honeypots protocol/action records, Honeytrap `attack_connection` records, ADBHoney, Medpot source-IP records, p0f JSON, and nginx JSON access records. Other JSON formats require compatible fields and are not guaranteed semantic support. Source IP must be valid; unsupported records are counted in coverage.

p0f records are categorized as passive; nginx/dashboard records as management. These stay in normalized exports and category totals but are excluded from main honeypot rankings and rules. Keep original T-Pot directory names when copying files so sensor classification remains accurate. Honeypot connection logs may include benign research scanners. A source is not automatically malicious.

Counts are **events**, not unique attacks. Cowrie connection and authentication metrics use explicit event IDs. Sessions count distinct `(sensor type, sensor ID, source IP, session ID)` tuples observed, including sessions that began outside the window. No attempt is made to join Honeytrap and another sensor's observation into one connection. Protocol labels may be transport-level (`tcp`) rather than application services. Port numbers alone do not prove a specific service.

By default all records count, including repeated copies. `--deduplicate` removes identical canonical JSON records within the same sensor/category, across files. This is useful for overlapping exports but can remove legitimate repeated identical events, especially untimestamped ones. It is not connection deduplication.

Rules in `RULES` at the top of `analyze.py` identify discovery, download commands, permission changes, persistence/mining/destructive indicators, sensitive web paths, and possible AI/MCP probes. Rules scan command inputs, URI fields, and up to 64 KiB of Honeytrap hex-decoded payload. They do not scan arbitrary base64 or encrypted traffic, emulate a shell, fetch URLs, inspect captured binaries, or execute commands. Unknown variants and obfuscation can evade matches. No match is not proof of absence. Rule matches do not prove exploitation or malicious intent.

Captured `downloads`, `attacks`, `binaries`, and `tty` directories are skipped. ZIP members are never extracted. Default decompressed limit is 256 MiB per log and 4 MiB per line; limit violations are reported. The program holds normalized events in memory, so use time-scoped exports for very large datasets (time filtering happens after ingestion). Aggregate archive size and number of files are not bounded. Run without administrator/root privileges.

## Optional offline geolocation / ASN enrichment

Supply your own lookup table:

```csv
ip,country,asn,organization
192.0.2.10,Example country,AS64500,Example provider
```

```powershell
py -3 .\analyze.py "C:\Logs" --out report-geo --geo-csv .\ip_lookup.csv
```

This is an exact-IP join in `source_ips.csv`, not a bundled GeoIP database or automatic lookup. Missing values are Unknown. Maintain the lookup table separately; geolocation is approximate and identifies infrastructure, not the person operating it. No IP reputation score or threat-actor attribution is invented.

## Validation

```powershell
py -3 -m unittest -v
```

The included tests cover time filtering, exclusions, redaction, malicious HTML and CSV content, gzip/ZIP input, duplicate handling, and sensor separation. Exit code 0 means honeypot events were analyzed; 2 means invalid arguments or no honeypot events. Coverage errors can coexist with exit code 0: always inspect `coverage.json`.
