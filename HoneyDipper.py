#!/usr/bin/env python3
"""Offline honeypot analyzer. Python 3.10+, standard library only."""
import argparse
import collections
import csv
import datetime as dt
import gzip
import hashlib
import html
import io
import ipaddress
import json
import pathlib
import re
import statistics
import sys
import urllib.parse
import zipfile
import zlib

UTC = dt.timezone.utc
VERSION = '1.1.0'
# Rule scope: 'cmd' = shell command only; 'web' = request URI and captured payload only;
# 'any' = all three. Shell-only words such as "id" or "curl" would otherwise match JSON-RPC
# bodies and User-Agent headers. Gaps are bounded ({0,200}) so hostile input cannot cause
# catastrophic backtracking.
_GAP = r'[^;&|\n]{0,200}?'
_RULES = [
    ('System discovery', 'cmd', r'\b(?:uname|whoami|id|lscpu|hostname)\b|/proc/(?:cpuinfo|meminfo)'),
    ('Download command', 'cmd', r'\b(?:wget|curl|tftp|ftpget)\b'),
    ('Download command', 'web', r'(?:[;|&`]|\$\()\s{0,20}(?:wget|curl|tftp|ftpget)\s'),
    ('Permissions change', 'any', r'\bchmod\b'),
    ('Persistence indicator', 'any', r'\bcrontab\b|authorized_keys|/etc/cron|systemctl\s+enable'),
    ('Mining indicator', 'any', r'\bxmrig\b|stratum\+tcp|\bminerd\b'),
    ('Destructive command indicator', 'any',
     r'\brm\b(?=' + _GAP + r'(?:\s-[a-z]*r|\s--recursive\b))(?=' + _GAP + r'(?:\s-[a-z]*f|\s--force\b))'),
    ('MCP endpoint probe', 'web', r'(?:^|/)mcp(?:[/?\s]|$)|\btools/list\b|\bresources/list\b'),
    ('AI endpoint probe', 'web', r'/api/(?:tags|generate|chat)(?:[/?\s]|$)|/v1/(?:models|chat/completions|completions)(?:[/?\s]|$)|\bollama\b|\bopenai\b'),
    ('Sensitive web path probe', 'web', r'/\.env\b|/\.git(?:[/?\s]|$)|/wp-login\.php|/actuator(?:[/?\s]|$)'),
]
RULES = [(label, scope, re.compile(pattern, re.I | re.M)) for label, scope, pattern in _RULES]
CMD_CAP, URI_CAP, BODY_CAP = 8192, 8192, 32768
LINE_CAP = 4 * 1024 * 1024
SAMPLE_CAP = 1000

# Command normalization: collapse the parts of a command that attackers randomize per
# victim (URLs, IPs, hashes, keys, random tokens, numbers) so that variants of the same
# script hash to the same campaign. Order matters: URLs before IPs before generic tokens.
# Every pattern is linear-time on hostile input and input is capped at CMD_CAP.
_NORM = [
    (re.compile(r'\b(?:https?|ftp|tftp)://[^\s\'"<>|;&`)\\]{1,2048}', re.I), '<URL>'),
    (re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?!\.?\d)'), '<IP>'),
    (re.compile(r'(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,64}(?![0-9A-Fa-f])'), '<HASH>'),
    (re.compile(r'[A-Za-z0-9+]{40,}={0,2}'), '<B64>'),
    (re.compile(r'\b(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{10,}\b'), '<TOKEN>'),
    (re.compile(r'\b\d{3,}\b'), '<NUM>'),
]
URL_RE = re.compile(r'\b(?:https?|ftp|tftp)://[^\s\'"<>|;&`)\\]{1,2048}', re.I)
IPV4_RE = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)')
HASH_RE = re.compile(r'(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])')
HASH_KIND = {64: 'sha256', 40: 'sha1', 32: 'md5'}
ENV_ASSIGN = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')
WRAPPERS = {'sudo', 'nohup', 'exec', 'time', 'nice', 'env'}

def normalize_command(cmd):
    s = cmd[:CMD_CAP]
    for pattern, token in _NORM:
        s = pattern.sub(token, s)
    return ' '.join(s.split())

def base_binaries(cmd):
    """First real binary of each chained segment: 'uname -a; nproc | wc -l' -> uname, nproc, wc."""
    found = []
    for part in re.split(r'&&|\|\||[;|&\n]', cmd[:CMD_CAP])[:200]:
        for tok in part.replace('$(', ' ').replace('`', ' ').strip(' (){}\t').split():
            if ENV_ASSIGN.match(tok) or tok in WRAPPERS:
                continue
            name = tok.rsplit('/', 1)[-1].lower()
            if re.fullmatch(r'[\w.+-]{1,64}', name):
                # Random dropper names (./4e6bcd5b0bc77c1c.sh) collapse to <TOKEN>.sh
                found.append(normalize_command(name))
            break
    return found

def extract_iocs(text):
    """Returns a set of (kind, value): url, ip, domain, md5/sha1/sha256."""
    text = text[:CMD_CAP]
    found = set()
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip('.,')
        found.add(('url', url))
        try:
            host = urllib.parse.urlsplit(url).hostname
        except ValueError:
            host = None
        if host:
            try:
                found.add(('ip', str(ipaddress.ip_address(host))))
            except ValueError:
                found.add(('domain', host.lower()))
    for m in IPV4_RE.finditer(text):
        try:
            found.add(('ip', str(ipaddress.IPv4Address(m.group(0)))))
        except ValueError:
            pass
    for m in HASH_RE.finditer(text):
        found.add((HASH_KIND[len(m.group(0))], m.group(0).lower()))
    return found

def defang(value, kind='url'):
    if kind not in ('url', 'ip', 'domain'):
        return value
    return re.sub(r'^(https?|ftp)', lambda m: {'http': 'hxxp', 'https': 'hxxps', 'ftp': 'fxp'}[m.group(1).lower()], value, flags=re.I).replace('.', '[.]')

def timestamp(value):
    if value is None or value == '':
        return None
    try:
        if isinstance(value, (int, float)):
            return dt.datetime.fromtimestamp(value, UTC)
        s = str(value).strip()
        # Python 3.10 fromisoformat only accepts 3- or 6-digit fractions and +HH:MM offsets.
        s = re.sub(r'(?<=:\d\d)\.(\d+)', lambda m: '.' + m.group(1)[:6].ljust(6, '0'), s)
        s = re.sub(r'(?<=\d)([+-])(\d{2})(\d{2})$', r'\1\2:\3', s)
        try:
            t = dt.datetime.fromisoformat(s.replace('Z', '+00:00'))
        except ValueError:
            t = dt.datetime.strptime(s, '%Y/%m/%d %H:%M:%S')
        return t.replace(tzinfo=UTC) if t.tzinfo is None else t.astimezone(UTC)
    except (ValueError, TypeError, OverflowError, OSError):
        return None

def pick(d, *keys):
    return next((d[k] for k in keys if d.get(k) is not None and d[k] != ''), '')

def normalize(d, name):
    if not isinstance(d, dict):
        return None
    if isinstance(d.get('_source'), dict):
        d = d['_source']
    path = name.replace('\\', '/').replace('!', '/').lower()
    c = d.get('attack_connection')
    c = c if isinstance(c, dict) else {}
    src = pick(d, 'src_ip', 'source_ip', 'client_ip') or c.get('remote_ip', '')
    try:
        addr = ipaddress.ip_address(str(src))
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    src = str(addr)
    event = str(pick(d, 'eventid', 'action', 'event_type') or ('honeytrap.capture' if c else 'observation'))
    sensor = event.split('.')[0] if '.' in event else next((s for s in ('p0f','nginx','medpot','dicompot','honeypots','honeytrap','adbhoney','cowrie') if s in path.split('/')), 'generic')
    category = 'passive' if 'client_ip' in d and 'mod' in d else ('management' if 'nginx' in path.split('/') or 'request_id' in d and 'upstream' in d else 'honeypot')
    data = d.get('data') if isinstance(d.get('data'), dict) else {}
    # Only the input event: cowrie.command.failed/.success repeat the same input string.
    command = str(d.get('input', '')) if event.endswith('command.input') else ''
    uri = str(pick(d, 'request_uri', 'url') or pick(data, 'uri', 'url'))
    payload = c.get('payload', {})
    payload = payload if isinstance(payload, dict) else {}
    body = ''
    if payload.get('data_hex'):
        try:
            body = bytes.fromhex(payload['data_hex'][:131072]).decode('utf-8', errors='replace')
        except (ValueError, TypeError):
            pass
    texts = {'cmd': command[:CMD_CAP], 'web': uri[:URI_CAP] + '\n' + body[:BODY_CAP]}
    texts['any'] = texts['cmd'] + '\n' + texts['web']
    tags, evidence = [], {}
    for label, scope, pattern in RULES:
        if label in evidence:
            continue
        m = pattern.search(texts[scope])
        if m:
            tags.append(label)
            evidence[label] = (texts[scope][m.start():m.start() + 160].splitlines() or [''])[0]
    # Cowrie session metadata used for session reconstruction and fingerprinting.
    duration = None
    if event == 'cowrie.session.closed':
        try:
            duration = float(d.get('duration'))
        except (TypeError, ValueError):
            pass
    return dict(timestamp=timestamp(pick(d, 'timestamp', '@timestamp', 'time_iso8601', 'start_time', 'unixtime')),
                source_ip=src, sensor=sensor, category=category, event=event,
                port=str(pick(d, 'dst_port', 'dest_port', 'server_port') or c.get('local_port', '')),
                protocol=str(pick(d, 'protocol') or c.get('protocol') or ''),
                session=str(d.get('session', '')), sensor_id=str(d.get('sensor','')),
                command=command, uri=uri, username=str(d.get('username', '')),
                password=str(d.get('password', '')), tags=tags, evidence=evidence,
                sha256=str(d.get('shasum','')) if 'download' in event or 'upload' in event else '',
                download_url=str(d.get('url', '')) if 'download' in event else '',
                hassh=str(d.get('hassh', '')),
                client_version=str(d.get('version', '')) if event == 'cowrie.client.version' else '',
                duration=duration,
                file=name)

def log_candidate(name):
    p = pathlib.PurePosixPath(name.replace('\\', '/'))
    if any(x.lower() in ('downloads', 'attacks', 'binaries', 'tty') for x in p.parts):
        return False
    # Allows numeric (.1) and date-style (.2026-10-28, -20261028) rotation suffixes.
    return bool(re.search(r'\.(?:json|jsonl|ndjson|log)(?:[.-](?:\d+|\d{4}-\d{2}-\d{2}))?(?:\.gz)?$', p.name, re.I))

def sources(paths, audit, limit):
    visited = set()
    for arg in paths:
        root = pathlib.Path(arg)
        files = sorted(root.rglob('*')) if root.is_dir() else [root]
        for p in files:
            if not p.is_file() or p.is_symlink() or p.resolve() in visited:
                continue
            visited.add(p.resolve())
            # Display names never contain the absolute local path; the directory filter
            # in log_candidate sees the path relative to the input root.
            if root.is_dir():
                rel = p.relative_to(root).as_posix()
                shown = (root.resolve().name or 'root') + '/' + rel
            else:
                rel = shown = p.name
            if p.suffix.lower() == '.zip':
                try:
                    with zipfile.ZipFile(p) as z:
                        for member in z.infolist():
                            if member.is_dir():
                                continue
                            name = p.name + '!' + member.filename
                            if not log_candidate(member.filename):
                                audit.append(dict(file=name, status='not a supported log; not read'))
                                continue
                            if member.file_size > limit:
                                audit.append(dict(file=name, status='file size limit exceeded'))
                                continue
                            with z.open(member) as f:
                                yield name, f
                except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
                    audit.append(dict(file=p.name, status='archive error: ' + str(exc)))
            elif log_candidate(rel):
                with p.open('rb') as f:
                    yield shown, f
            else:
                audit.append(dict(file=shown, status='not a supported log; not read'))

def records(stream, name, audit, limit):
    counts = collections.Counter()
    digest = hashlib.sha256()
    try:
        source = gzip.GzipFile(fileobj=stream) if name.lower().endswith('.gz') else stream
        total = 0
        line_no = 0
        while True:
            raw = source.readline(min(LINE_CAP + 1, limit-total+1))
            if not raw:
                break
            total += len(raw)
            if total > limit:
                counts['limit_exceeded'] += 1
                break
            line_no += 1
            if len(raw) > LINE_CAP:
                # One oversized line must not abandon the rest of the file: discard through
                # the next newline, count it, and keep going (line numbers stay accurate).
                # Discarded bytes are not part of sha256_read_content.
                counts['oversized_lines'] += 1
                over_total = False
                while not raw.endswith(b'\n'):
                    raw = source.readline(LINE_CAP)
                    if not raw:
                        break
                    total += len(raw)
                    if total > limit:
                        over_total = True
                        break
                if over_total:
                    counts['limit_exceeded'] += 1
                    break
                continue
            digest.update(raw)
            if not raw.strip():
                continue
            counts['nonblank_lines'] += 1
            try:
                d = json.loads(raw)
            except (ValueError, RecursionError):
                counts['non_json_lines'] += 1
                continue
            counts['json_lines'] += 1
            e = normalize(d, name)
            if e is None:
                counts['unsupported_records'] += 1
                continue
            counts['normalized_records'] += 1
            e['line'] = line_no
            yield e, d
    except (OSError, EOFError, ValueError, TypeError, zlib.error, zipfile.BadZipFile,
            RuntimeError, NotImplementedError) as exc:
        # zlib.error: corrupt .gz; BadZipFile/RuntimeError/NotImplementedError: bad CRC,
        # encrypted or unsupported ZIP members. One bad file must not abort the whole run.
        counts['read_errors'] += 1
        audit.append(dict(file=name, status='read error: '+str(exc)))
    finally:
        audit.append(dict(file=name, status='parsed', sha256_read_content=digest.hexdigest(), **counts))

def safe_csv(value):
    s = str(value)
    return "'" + s if s.lstrip().startswith(('=', '+', '-', '@')) or s.startswith(('\t','\r','\n')) else s

def lo(a, b):
    return b if a is None else a if b is None else min(a, b)

def hi(a, b):
    return b if a is None else a if b is None else max(a, b)

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('inputs', nargs='+', help='JSONL logs, log directories, or ZIP archives')
    p.add_argument('--out', default='honeypot-report', help='NEW output directory (must not exist)')
    p.add_argument('--exclude-ip', action='append', default=[], help='Source IP or CIDR; repeatable')
    p.add_argument('--redact', action='append', default=[], help='Literal string (case-insensitive) to remove from every output; repeatable')
    p.add_argument('--start', help='Inclusive ISO timestamp; unspecified timezone means UTC')
    p.add_argument('--end', help='Exclusive ISO timestamp; unspecified timezone means UTC')
    p.add_argument('--first-hours', type=float, help='Window from earliest eligible honeypot event')
    p.add_argument('--deduplicate', action='store_true', help='Drop exact canonical JSON duplicates within the same sensor/category')
    p.add_argument('--geo-csv', help='Optional offline IP lookup CSV: ip,country,asn,organization')
    p.add_argument('--max-file-mb', type=int, default=256, help='Per-log decompressed byte limit')
    p.add_argument('--top', type=int, default=30, help='Rows per table in report.html (CSV files always hold every row)')
    p.add_argument('--no-defang', action='store_true', help='Write raw URLs/IPs/domains in iocs.csv and downloads.csv (default: defanged)')
    args = p.parse_args(argv)
    start, end = timestamp(args.start), timestamp(args.end)
    if (args.start and start is None) or (args.end and end is None):
        p.error('Invalid ISO timestamp')
    if start and end and start >= end:
        p.error('--start must be before --end')
    if args.first_hours is not None and args.first_hours <= 0 or args.max_file_mb <= 0 or args.top <= 0:
        p.error('Limits must be positive')
    for arg in args.inputs:
        if not pathlib.Path(arg).exists():
            p.error('Input does not exist: '+arg)
    try:
        networks = [ipaddress.ip_network(ip, strict=False) for ip in args.exclude_ip]
    except ValueError as exc:
        p.error(str(exc))
    out = pathlib.Path(args.out)
    if out.exists():
        p.error('Output already exists. Choose a new --out directory.')
    audit, events, seen = [], [], set()
    excluded = duplicates = 0
    for name, stream in sources(args.inputs, audit, args.max_file_mb*1024*1024):
        for event, raw in records(stream, name, audit, args.max_file_mb*1024*1024):
            ip = ipaddress.ip_address(event['source_ip'])
            if any(ip in net for net in networks):
                excluded += 1
                continue
            if args.deduplicate:
                key = (event['sensor'], event['category'], hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).digest())
                if key in seen:
                    duplicates += 1
                    continue
                seen.add(key)
            events.append(event)
    if args.first_hours:
        times = [e['timestamp'] for e in events if e['category']=='honeypot' and e['timestamp'] and (not start or e['timestamp']>=start) and (not end or e['timestamp']<end)]
        if not times:
            p.error('No timestamped honeypot events for --first-hours')
        start = min(times)
        cutoff = start + dt.timedelta(hours=args.first_hours)
        end = min(end, cutoff) if end else cutoff
    filtered, untimed = 0, sum(e['timestamp'] is None for e in events)
    if start or end:
        kept = [e for e in events if e['timestamp'] and (not start or e['timestamp']>=start) and (not end or e['timestamp']<end)]
        filtered = len(events)-len(kept)
        events = kept
    events.sort(key=lambda e: (e['timestamp'] or dt.datetime.min.replace(tzinfo=UTC), e['file'], e['line']))
    hp = [e for e in events if e['category']=='honeypot']
    counts = collections.Counter(e['event'] for e in hp)
    times = [e['timestamp'] for e in hp if e['timestamp']]
    geo = {}
    if args.geo_csv:
        with open(args.geo_csv, encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            if not {'ip','country','asn','organization'}.issubset(reader.fieldnames or []):
                p.error('Geo CSV requires ip,country,asn,organization headers')
            geo = {r['ip']: r for r in reader}
    redactions = sorted(set(x for x in args.redact if x), key=len, reverse=True)
    redact_re = re.compile('|'.join(re.escape(x) for x in redactions), re.I) if redactions else None
    def clean(value):
        if isinstance(value, dict):
            return {clean(k):clean(v) for k,v in value.items()}
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, dt.datetime):
            return value.isoformat()
        if isinstance(value, str) and redact_re:
            value = redact_re.sub('[REDACTED]', value)
        return value
    def cell(value):
        value = clean(value)
        if value is None:
            return ''
        if isinstance(value, (list, tuple)):
            value = '; '.join(str(v) for v in value)
        return safe_csv(value)
    def write_csv(name, rows, headers):
        with (out/name).open('w', newline='', encoding='utf-8-sig') as f:
            w = csv.writer(f)
            w.writerow(headers)
            for row in rows:
                w.writerow([cell(v) for v in row])
    def df(value, kind):
        return value if args.no_defang else defang(value, kind)
    def skey(e):
        return (e['sensor'], e['sensor_id'], e['source_ip'], e['session'])
    def tally(items):
        """(value, event) pairs -> rows of (value, events, unique_ips, sessions), largest first."""
        agg = {}
        for value, e in items:
            a = agg.setdefault(value, [0, set(), set()])
            a[0] += 1
            a[1].add(e['source_ip'])
            if e['session']:
                a[2].add(skey(e))
        return sorted(((v, a[0], len(a[1]), len(a[2])) for v, a in agg.items()), key=lambda r: (-r[1], str(r[0])))

    # --- Session reconstruction -------------------------------------------------------
    sess = {}
    for e in hp:
        if not e['session']:
            continue
        s = sess.setdefault(skey(e), dict(
            sensor=e['sensor'], sensor_id=e['sensor_id'], source_ip=e['source_ip'], session=e['session'],
            start=None, end=None, events=0, failed=0, ok=0, creds=set(), ok_users=[], commands=[],
            urls=[], hashes=[], tags=set(), hassh='', client_version='', closed=None))
        s['events'] += 1
        s['start'], s['end'] = lo(s['start'], e['timestamp']), hi(s['end'], e['timestamp'])
        if e['event'] == 'cowrie.login.failed':
            s['failed'] += 1
            s['creds'].add((e['username'], e['password']))
        elif e['event'] == 'cowrie.login.success':
            s['ok'] += 1
            s['creds'].add((e['username'], e['password']))
            s['ok_users'].append(e['username'])
        if e['command']:
            s['commands'].append(clean(e['command']))
        if e['download_url']:
            s['urls'].append(clean(e['download_url']))
        if e['sha256'] and e['sha256'] not in s['hashes']:
            s['hashes'].append(e['sha256'])
        s['tags'].update(e['tags'])
        s['hassh'] = s['hassh'] or e['hassh']
        s['client_version'] = s['client_version'] or e['client_version']
        if e['duration'] is not None:
            s['closed'] = e['duration']
    sess_rows, campaigns, durations = [], {}, []
    floor = dt.datetime.min.replace(tzinfo=UTC)
    for k, s in sorted(sess.items(), key=lambda kv: (kv[1]['start'] or floor, kv[0])):
        if s['closed'] is not None:
            dur = s['closed']
        elif s['start'] and s['end']:
            dur = (s['end'] - s['start']).total_seconds()
        else:
            dur = None
        if dur is not None:
            dur = round(dur, 3)
            durations.append(dur)
        norm = [normalize_command(c) for c in s['commands']]
        cid = hashlib.sha256('\n'.join(norm).encode('utf-8', 'replace')).hexdigest()[:12] if norm else ''
        if cid:
            c = campaigns.setdefault(cid, dict(norm=norm, sessions=0, ips=set(), first=None, last=None,
                                               sample=s['commands'], tags=set()))
            c['sessions'] += 1
            c['ips'].add(s['source_ip'])
            c['first'], c['last'] = lo(c['first'], s['start']), hi(c['last'], s['end'])
            c['tags'].update(s['tags'])
        sess_rows.append([s['sensor'], s['sensor_id'], s['source_ip'], s['session'], s['start'], s['end'], dur,
                          s['events'], s['failed'] + s['ok'], 'yes' if s['ok'] else 'no', len(s['creds']),
                          '; '.join(dict.fromkeys(s['ok_users'])), len(s['commands']), len(s['urls']),
                          ' '.join(dict.fromkeys(df(u, 'url') for u in s['urls'])), ' '.join(s['hashes']),
                          sorted(s['tags']), s['hassh'], s['client_version'], cid])
    campaign_rows = sorted(campaigns.items(), key=lambda kv: (-kv[1]['sessions'], kv[0]))

    # --- Downloads and indicators -------------------------------------------------------
    dl = {}
    iocs = {}
    for e in hp:
        if e['download_url'] or e['sha256']:
            a = dl.setdefault((clean(e['download_url']), e['sha256']), [0, set(), set(), None, None])
            a[0] += 1
            a[1].add(e['source_ip'])
            if e['session']:
                a[2].add(skey(e))
            a[3], a[4] = lo(a[3], e['timestamp']), hi(a[4], e['timestamp'])
        found = set()
        if e['command']:
            found |= extract_iocs(clean(e['command']))
        if e['download_url']:
            found |= extract_iocs(clean(e['download_url']))
        if e['sha256']:
            found.add(('sha256', clean(e['sha256']).lower()))
        for ioc in found:
            a = iocs.setdefault(ioc, [0, set(), set(), None, None])
            a[0] += 1
            a[1].add(e['source_ip'])
            if e['session']:
                a[2].add(skey(e))
            a[3], a[4] = lo(a[3], e['timestamp']), hi(a[4], e['timestamp'])
    dl_rows = sorted(((df(u, 'url') if u else '', h, a[0], len(a[1]), len(a[2]), a[3], a[4]) for (u, h), a in dl.items()),
                     key=lambda r: (-r[2], r[0], r[1]))
    ioc_rows = sorted(((kind, df(val, kind), a[0], len(a[1]), len(a[2]), a[3], a[4]) for (kind, val), a in iocs.items()),
                      key=lambda r: (-r[2], r[0], r[1]))

    summary = dict(version=VERSION, honeypot_events=len(hp), unique_source_ips=len({e['source_ip'] for e in hp}),
                   category_counts=dict(collections.Counter(e['category'] for e in events)),
                   cowrie_connections=counts['cowrie.session.connect'], cowrie_accepted_logins=counts['cowrie.login.success'],
                   cowrie_failed_logins=counts['cowrie.login.failed'], command_events=sum(bool(e['command']) for e in hp),
                   sessions_with_ids=len({skey(e) for e in hp if e['session']}),
                   sessions_with_commands=sum(bool(s['commands']) for s in sess.values()),
                   sessions_with_login_success=sum(s['ok'] > 0 for s in sess.values()),
                   campaigns=len(campaigns),
                   median_session_duration_s=round(statistics.median(durations), 3) if durations else None,
                   download_events=sum(bool(e['download_url'] or e['sha256']) for e in hp),
                   unique_download_hashes=len({e['sha256'] for e in hp if e['sha256']}),
                   unique_iocs=len(iocs),
                   first_event=min(times).isoformat() if times else None, last_event=max(times).isoformat() if times else None,
                   excluded_source_events=excluded, duplicate_events_removed=duplicates, time_filtered_events=filtered,
                   missing_timestamps_before_time_filter=untimed,
                   start=start.isoformat() if start else None, end=end.isoformat() if end else None,
                   deduplicate=args.deduplicate)

    out.mkdir(parents=True)
    (out/'summary.json').write_text(json.dumps(clean(summary), indent=2), encoding='utf-8')
    (out/'coverage.json').write_text(json.dumps(clean(audit), indent=2), encoding='utf-8')
    fields = [k for k in events[0] if k != 'evidence'] if events else ['timestamp','source_ip','event']
    with (out/'events.jsonl').open('w', encoding='utf-8') as f:
        for e in events:
            f.write(json.dumps(clean(e), ensure_ascii=True)+'\n')
    write_csv('events.csv', ([e.get(k,'') for k in fields] for e in events), fields)
    tables = {}
    for title, field in [('Services','protocol'), ('Ports','port'), ('Event types','event'), ('Commands','command'), ('HTTP paths','uri'), ('Usernames','username'), ('Passwords','password')]:
        # Count after redaction so values that redact to the same text merge into one row.
        rows = tally((clean(e[field]), e) for e in hp if e[field] != '')
        tables[title] = ([field.capitalize(), 'Events', 'Unique IPs', 'Sessions'], rows)
        write_csv(title.lower().replace(' ','_')+'.csv', rows, [field,'events','unique_ips','sessions'])
    rows = tally((b, e) for e in hp if e['command'] for b in sorted(set(base_binaries(clean(e['command'])))))
    tables['Command binaries'] = (['Binary', 'Events', 'Unique IPs', 'Sessions'], rows)
    write_csv('command_binaries.csv', rows, ['binary','events','unique_ips','sessions'])
    write_csv('sessions.csv', sess_rows, ['sensor','sensor_id','source_ip','session','start_utc','end_utc','duration_s','events',
                                          'login_attempts','login_success','distinct_credentials','successful_usernames',
                                          'commands','downloads','download_urls','sha256s','rule_tags','hassh','client_version','campaign_id'])
    camp_csv = [(cid, c['sessions'], len(c['ips']), c['first'], c['last'], len(c['norm']), sorted(c['tags']),
                 ' ⏎ '.join(c['norm']), (' ⏎ '.join(c['sample']))[:SAMPLE_CAP]) for cid, c in campaign_rows]
    write_csv('campaigns.csv', camp_csv, ['campaign_id','sessions','unique_ips','first_seen','last_seen','commands_per_session',
                                          'rule_tags','normalized_sequence','sample_raw_commands'])
    tables['Campaigns'] = (['Normalized command sequence', 'Sessions', 'Unique IPs', 'Campaign'],
                           [((' ⏎ '.join(c['norm']))[:300], c['sessions'], len(c['ips']), cid) for cid, c in campaign_rows])
    write_csv('downloads.csv', dl_rows, ['url','sha256','events','unique_ips','sessions','first_seen','last_seen'])
    tables['Downloads'] = (['URL', 'Events', 'Unique IPs', 'SHA-256'], [(r[0], r[2], r[3], r[1]) for r in dl_rows])
    write_csv('iocs.csv', ioc_rows, ['type','indicator','events','unique_ips','sessions','first_seen','last_seen'])
    tables['Indicators'] = (['Indicator', 'Events', 'Unique IPs', 'Type'], [(r[1], r[2], r[3], r[0]) for r in ioc_rows])
    rules = collections.Counter(tag for e in hp for tag in e['tags'])
    tables['Rule matches'] = (['Value', 'Events'], rules.most_common())
    write_csv('rule_matches.csv', ((e['timestamp'],e['source_ip'],tag,e['command'] or e['uri'],e['evidence'].get(tag,''),e['file'],e['line']) for e in hp for tag in e['tags']), ['timestamp','source_ip','rule','command_or_uri','matched_text','file','line'])
    hourly = collections.Counter(e['timestamp'].strftime('%Y-%m-%d %H:00 UTC') for e in hp if e['timestamp'])
    tables['Hourly activity'] = (['Value', 'Events'], sorted(hourly.items()))
    write_csv('hourly.csv', tables['Hourly activity'][1], ['hour_utc','events'])
    ipcounts = collections.Counter(clean(e['source_ip']) for e in hp)
    ip_sessions, ip_seen = collections.defaultdict(set), {}
    for e in hp:
        if e['session']:
            ip_sessions[e['source_ip']].add(skey(e))
        a = ip_seen.get(e['source_ip'], (None, None))
        ip_seen[e['source_ip']] = (lo(a[0], e['timestamp']), hi(a[1], e['timestamp']))
    ip_rows = sorted(ipcounts.items(), key=lambda kv: (-kv[1], kv[0]))
    tables['Source IPs'] = (['Value', 'Events', 'Sessions'], [(ip, n, len(ip_sessions[ip])) for ip, n in ip_rows])
    write_csv('source_ips.csv', ((ip,n,geo.get(ip,{}).get('country','Unknown'),geo.get(ip,{}).get('asn',''),geo.get(ip,{}).get('organization',''),
                                  len(ip_sessions[ip]),ip_seen[ip][0],ip_seen[ip][1]) for ip,n in ip_rows),
              ['source_ip','events','country','asn','organization','sessions','first_seen','last_seen'])
    esc = lambda v: html.escape(str(clean(v)))
    sections = []
    for title, (headers, rows) in tables.items():
        maximum = max((r[1] for r in rows), default=1) or 1
        head = ''.join(f'<th>{html.escape(h)}</th>' for h in headers) + '<th>Volume</th>'
        body = ''.join('<tr><td><code>' + esc(r[0]) + '</code></td>' + ''.join(f'<td>{esc(c)}</td>' for c in r[1:])
                       + f'<td><meter min="0" max="{maximum}" value="{r[1]}"></meter></td></tr>' for r in rows[:args.top])
        sections.append(f'<section><h2>{title}</h2><p>Top {args.top}; full values in CSV.</p><table><tr>{head}</tr>{body}</table></section>')
    metrics = ''.join(f'<div class="card"><strong>{esc(summary[k])}</strong><br>{k.replace("_"," ")}</div>' for k in ['honeypot_events','unique_source_ips','cowrie_connections','cowrie_accepted_logins','command_events','sessions_with_commands','campaigns'])
    report = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>Honeypot analysis</title><style>body{font:16px system-ui;background:#f0f4f8;color:#152238;max-width:1100px;margin:auto;padding:30px}h1{font-size:36px}.cards{display:flex;flex-wrap:wrap;gap:12px}.card,section{background:white;padding:20px;border-radius:10px;margin:12px 0}.card strong{font-size:28px;color:#096d78}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid #dde4eb;overflow-wrap:anywhere}code{white-space:pre-wrap;overflow-wrap:anywhere}meter{width:100px}pre{white-space:pre-wrap}@media print{body{background:white;padding:0}section{break-inside:avoid}}</style><h1>Honeypot telemetry report</h1>'''
    report += f'<p>Offline deterministic analysis • v{VERSION} • UTC</p><div class="cards">{metrics}</div>'
    report += '<section><h2>Interpretation and coverage</h2><p>Events are log records, not unique attacks or attackers. Source IPs do not identify people. Accepted logins represent honeypot behavior, not production compromise. Rule matches are indicators for review, not malware attribution or confirmed exploitation. AI endpoint paths can overlap with ordinary APIs.</p><p>Passive and management records are excluded from the main totals. No cross-sensor connection deduplication is attempted. Event counts let chatty services rank higher, so tables also show unique IPs and sessions. Sessions are keyed by sensor, sensor id, source IP and session id; duration comes from the session-closed event when present, otherwise first-to-last event. Campaigns group sessions whose ordered commands are identical after URLs, IPs, hashes, keys, random tokens and numbers are replaced with placeholders: a heuristic, so near-identical scripts can still split and unrelated scripts can merge. Indicators (URLs, IPs, domains, hashes) are extracted from shell commands and download records only, and are defanged unless --no-defang is used. Naive timestamps are assumed UTC. Unknown timestamps are omitted when a time filter is set. See coverage.json for skipped files, unsupported records, oversized lines, and parse/size errors. Text-only logs and binary artifacts are not analyzed. Geo data is supplied by the user; no live lookup is performed. Rules read at most 8 KB of each command or URI and 32 KB of each captured payload.</p>'
    report += '<pre>'+esc(json.dumps(summary, indent=2))+'</pre></section>'+''.join(sections)+'</html>'
    (out/'report.html').write_text(report, encoding='utf-8')
    print(json.dumps(clean(summary), indent=2))
    print('Report: '+str(out/'report.html'))
    return 0 if hp else 2

if __name__ == '__main__':
    sys.exit(main())
