"""
Known vulnerabilities in a session's devices: security advisories in CSAF 2.0, the format CISA publishes
its ICS advisories in (as do Siemens, Schneider Electric, Hitachi Energy and others for their own),
matched against the vendor, model, order number and firmware devices reported in the capture.

A match is a lead to check, not a finding. Advisories name products in free text, so a device is
matched by its order or model number where the advisory lists them, otherwise by its model name, or
by the product family its order number belongs to; the match says which. Affected versions are
mostly written as ranges ('vers:intdot/<4.5.0', '<= 5.008', '<V18_Update_2'): a device whose firmware
is in the range is affected, and one whose firmware wasn't seen, or whose range pyLot can't read, is
possibly affected.

Usage, with the same database as the web app (PYLOT_DB_PATH):
    python advisories.py fetch                 download and import CISA's ICS advisories
    python advisories.py import FILE...        import CSAF files, or .zip or .tar.gz archives of them
"""
import argparse
import io
import json
import os
import re
import sys
import tarfile
import urllib.request
import zipfile
from collections import defaultdict

import storage

CISA_ARCHIVE = 'https://codeload.github.com/cisagov/CSAF/tar.gz/refs/heads/develop'
CISA_FOLDER = 'csaf_files/OT/'  # the archive also holds IT advisories, which don't concern control systems
MAX_DOCUMENT_BYTES = 20 * 1024 * 1024
MAX_FIX_LENGTH = 400

# --- reading CSAF

class NotAdvisory(ValueError):
    pass

def parse_csaf(document):
    """
    An advisory dict from a parsed CSAF document: id, title, publisher, url, released, updated, score,
    cves, and the affected products (vendor, product, models, versions, cves, score, fix).
    Raises NotAdvisory if it isn't a CSAF document with vulnerabilities.
    """
    if not isinstance(document, dict) or not isinstance(document.get('document'), dict):
        raise NotAdvisory('not a CSAF document')
    meta = document['document']
    tracking = meta.get('tracking') or {}
    if not str(meta.get('category', '')).startswith('csaf_') or not tracking.get('id'):
        raise NotAdvisory('not a CSAF document')
    products = {}
    _walk(document.get('product_tree') or {}, [], products)

    affected = defaultdict(lambda: {'cves': set(), 'score': None, 'fix': None})
    all_cves, top_score = set(), None
    for vulnerability in document.get('vulnerabilities') or []:
        cve = vulnerability.get('cve') or (vulnerability.get('ids') or [{}])[0].get('text')
        status = vulnerability.get('product_status') or {}
        ids = [pid for key in ('known_affected', 'first_affected', 'last_affected') for pid in status.get(key) or []]
        scores = {}
        for score in vulnerability.get('scores') or []:
            base = (score.get('cvss_v3') or score.get('cvss_v2') or {}).get('baseScore')
            if isinstance(base, (int, float)):
                for pid in score.get('products') or []:
                    scores[pid] = max(scores.get(pid, 0), base)
        fixes = {}
        for remediation in vulnerability.get('remediations') or []:
            if remediation.get('category') == 'vendor_fix' and remediation.get('details'):
                for pid in remediation.get('product_ids') or []:
                    fixes.setdefault(pid, remediation['details'])
        for pid in ids:
            if pid not in products:
                continue  # products made of others (relationships) aren't matched
            entry = affected[pid]
            if cve:
                entry['cves'].add(cve)
                all_cves.add(cve)
            if pid in scores:
                entry['score'] = max(entry['score'] or 0, scores[pid])
                top_score = max(top_score or 0, scores[pid])
            entry['fix'] = entry['fix'] or fixes.get(pid)
    if not affected:
        raise NotAdvisory('no affected products')

    rows = []
    for pid, entry in affected.items():
        vendor, product, models, versions = products[pid]
        rows.append({'vendor': vendor, 'product': product, 'models': ' '.join(models) or None, 'versions': versions,
                     'cves': ', '.join(sorted(entry['cves'])), 'score': entry['score'],
                     'fix': entry['fix'][:MAX_FIX_LENGTH] if entry['fix'] else None})
    return {'id': str(tracking['id'])[:100], 'title': str(meta.get('title') or tracking['id'])[:500],
            'publisher': (meta.get('publisher') or {}).get('name'), 'url': _advisory_url(meta, tracking['id']),
            'released': tracking.get('initial_release_date'), 'updated': tracking.get('current_release_date'),
            'score': top_score, 'cves': ', '.join(sorted(all_cves)), 'products': rows}

# Siemens-style order numbers (MLFB), which advisories often give in the product name: 6ES7212-1BE40-0XB0
ORDER_NUMBER = re.compile(r'\b6[A-Z]{2}\d\s?\d{3}-[0-9A-Z]{5}-[0-9A-Z]{4}\b')
MODEL_LIKE = re.compile(r'(?=.*\d)(?=.*[A-Z])[A-Z0-9][A-Z0-9\-/]{4,}')

def _walk(branch, path, products):
    """product id -> (vendor, product name, model numbers, versions) for every product in the tree."""
    for child in branch.get('branches') or []:
        if not isinstance(child, dict):
            continue
        here = path + [(child.get('category'), str(child.get('name') or ''))]
        product = child.get('product')
        if isinstance(product, dict) and product.get('product_id'):
            vendor = next((name for category, name in here if category == 'vendor'), '')
            names = [name for category, name in here if category in ('product_family', 'product_name')]
            version = here[-1][1] if here[-1][0] in ('product_version', 'product_version_range') else None
            helper = product.get('product_identification_helper') or {}
            models = [str(m) for m in (helper.get('model_numbers') or []) + (helper.get('skus') or [])]
            if version and parse_range(version) is None and MODEL_LIKE.fullmatch(version):
                models.append(version)  # some advisories put the affected models where the version goes: BMXNOC0402
                version = None
            models += [m for name in names for m in ORDER_NUMBER.findall(name) if m not in models]
            label = ' '.join(dict.fromkeys(names)) or product.get('name', '')
            products[product['product_id']] = (vendor.strip(), label.strip(), models, version)
        _walk(child, here, products)

def _advisory_url(meta, tracking_id):
    advisory = str(tracking_id).lower()
    if re.fullmatch(r'icsa-\d\d-\d{3}-\d\d[a-z]?', advisory):
        return f'https://www.cisa.gov/news-events/ics-advisories/{advisory}'
    if re.fullmatch(r'icsma-\d\d-\d{3}-\d\d[a-z]?', advisory):
        return f'https://www.cisa.gov/news-events/ics-medical-advisories/{advisory}'
    links = [r.get('url') for r in meta.get('references') or [] if r.get('category') == 'self' and r.get('url')]
    links = [url for url in links if str(url).startswith(('https://', 'http://'))]
    return next((url for url in links if not url.endswith('.json')), links[0] if links else None)

def read_documents(name, data):
    """Yield (name, parsed JSON) for a CSAF file, or for each one in a .zip or .tar(.gz) archive."""
    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.filename.endswith('.json') and not info.is_dir() and info.file_size <= MAX_DOCUMENT_BYTES:
                    yield from _load(info.filename, archive.read(info))
        return
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data))
    except tarfile.TarError:
        yield from _load(name, data)
        return
    with archive:
        for member in archive:
            if member.isfile() and member.name.endswith('.json') and member.size <= MAX_DOCUMENT_BYTES:
                yield from _load(member.name, archive.extractfile(member).read())

def _load(name, data):
    try:
        yield name, json.loads(data)
    except ValueError:
        yield name, None

# --- storing

def import_advisories(conn, documents):
    """
    Store the advisories among documents ((name, parsed JSON) pairs), replacing older revisions of the same
    advisory. Returns counts: added, updated, unchanged, and skipped (files that aren't CSAF advisories).
    """
    counts = {'added': 0, 'updated': 0, 'unchanged': 0, 'skipped': 0}
    with conn:
        for _, document in documents:
            try:
                advisory = parse_csaf(document)
            except (NotAdvisory, AttributeError, TypeError):
                counts['skipped'] += 1
                continue
            current = conn.execute("SELECT updated FROM advisories WHERE id = ?", (advisory['id'],)).fetchone()
            if current and (current['updated'] or '') >= (advisory['updated'] or ''):
                counts['unchanged'] += 1
                continue
            conn.execute("DELETE FROM advisories WHERE id = ?", (advisory['id'],))
            conn.execute("INSERT INTO advisories (id, title, publisher, url, released, updated, score, cves) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         tuple(advisory[k] for k in ('id', 'title', 'publisher', 'url', 'released', 'updated', 'score', 'cves')))
            conn.executemany("INSERT INTO advisory_products (advisory_id, vendor, product, models, versions, cves, score, fix) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                             [(advisory['id'], p['vendor'], p['product'], p['models'], p['versions'], p['cves'], p['score'], p['fix'])
                              for p in advisory['products']])
            counts['updated' if current else 'added'] += 1
        if counts['added'] or counts['updated']:
            conn.execute("INSERT INTO settings (key, value) VALUES ('advisories_revision', '1') ON CONFLICT (key) "
                         "DO UPDATE SET value = CAST(value AS INTEGER) + 1")
    return counts

def fetch_cisa(conn, url=CISA_ARCHIVE, timeout=120):
    """Download CISA's CSAF repository and import its ICS (OT) advisories."""
    request = urllib.request.Request(url, headers={'User-Agent': 'pyLot'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read()
    return import_advisories(conn, ((name, doc) for name, doc in read_documents('cisa.tar.gz', data) if CISA_FOLDER in name))

def advisory_summary(conn):
    row = conn.execute("SELECT COUNT(*) AS advisories, MAX(updated) AS newest, MAX(imported_at) AS imported_at FROM advisories").fetchone()
    products = conn.execute("SELECT COUNT(*) FROM advisory_products").fetchone()[0]
    publishers = [dict(r) for r in conn.execute("SELECT COALESCE(publisher, 'unknown') AS publisher, COUNT(*) AS advisories "
                                                "FROM advisories GROUP BY 1 ORDER BY 2 DESC")]
    return {**dict(row), 'products': products, 'publishers': publishers}

def delete_advisories(conn):
    with conn:
        conn.execute("DELETE FROM advisories")
        conn.execute("INSERT INTO settings (key, value) VALUES ('advisories_revision', '1') ON CONFLICT (key) "
                     "DO UPDATE SET value = CAST(value AS INTEGER) + 1")

# --- versions

ALL_VERSIONS = 'all'
# Words that may follow a version number without making it something else: V5.6 SP1 HF7, V18 Update 2, 6.0.3.3 RU1
SUFFIX_WORDS = {'sp', 'hf', 'update', 'upd', 'ru', 'fp', 'cp', 'build', 'patch', 'hotfix', 'rev', 'release', 'beta', 'firmware',
                'version', 'versions', 'and', 'or', 'prior', 'earlier', 'before', 'older', 'later', 'above', 'newer', 'all'}
UP_TO = re.compile(r'(?i)\b(and|or) (prior|earlier|before|older)\b|\bprior versions\b')
FROM = re.compile(r'(?i)\b(and|or) (later|above|newer)\b')

def _suffix_ok(suffix):
    return all(len(word) <= 2 or word in SUFFIX_WORDS for word in re.findall(r'[a-z]+', suffix.lower()))

def parse_version(text):
    """(numbers, suffix) for a version like 'V4.2.3', '4.007', 'R1.30.0' or '5.6_SP1'; None if it isn't one."""
    match = re.match(r'\s*(?:v|r|fw|version|firmware)?[\s_.]*(\d+(?:\.\d+)*)(.*)$', str(text), re.I)
    if not match:
        return None
    numbers = tuple(int(n) for n in match[1].split('.'))
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers = numbers[:-1]
    return numbers, match[2].strip()

def parse_range(text):
    """
    The versions an advisory says are affected, as ALL_VERSIONS or a list of (operator, numbers, suffix)
    with operators <, <=, >, >=, = and 'prefix' (2.x); None if pyLot can't read it.
    """
    if text is None:
        return ALL_VERSIONS
    text = str(text).strip()
    if text.lower().startswith('vers:'):
        text = text.split('/', 1)[1] if '/' in text else ''
    if text in ('', '*') or re.fullmatch(r'(?i)all(\s+versions)?', text):
        return ALL_VERSIONS
    constraints = []
    for part in re.split(r'\s*\|\s*|\s*,\s*|(?<=\w)_(?=[<>])|\s+(?=[<>]=?)', text):
        part = part.strip()
        if not part:
            continue
        match = re.fullmatch(r'(<=|>=|<|>|=)?\s*(.+)', part)
        operator, value = match[1] or '=', match[2]
        wildcard = re.fullmatch(r'(?i)v?(\d+(?:\.\d+)*)\.?x+', value)
        if wildcard and operator == '=':
            constraints.append(('prefix', tuple(int(n) for n in wildcard[1].split('.')), ''))
            continue
        version = parse_version(value)
        if version is None or not _suffix_ok(version[1]):
            return None
        numbers, suffix = version
        if operator == '=' and UP_TO.search(suffix):  # 2.3 and prior
            operator, suffix = '<=', UP_TO.sub('', suffix).strip()
        elif operator == '=' and FROM.search(suffix):  # 4.0 and later
            operator, suffix = '>=', FROM.sub('', suffix).strip()
        constraints.append((operator, numbers, suffix))
    return constraints or None

def _compare(a, b):
    return (a > b) - (a < b)

def in_range(constraints, firmware):
    """True if firmware is among the affected versions, False if not, None if that can't be told."""
    if constraints == ALL_VERSIONS:
        return True
    if constraints is None:
        return None
    version = parse_version(firmware)
    if version is None:
        return None
    numbers, suffix = version
    uncertain = False

    def holds(operator, bound, bound_suffix):
        nonlocal uncertain
        if operator == 'prefix':
            return numbers[:len(bound)] == bound
        order = _compare(numbers, bound)
        if order == 0 and (suffix or bound_suffix) and suffix != bound_suffix:
            uncertain = True  # V5.6 against <V5.6_SP1: depends on the service pack, which the device may not report
        return {'<': order < 0, '<=': order <= 0, '>': order > 0, '>=': order >= 0, '=': order == 0}[operator]

    # Ranges are written lower bound then upper bound: >=7.80|<8.90, or a single bound; several may follow each other
    lower, matched = None, False
    for operator, bound, bound_suffix in constraints:
        if operator in ('>', '>='):
            if lower is not None and holds(*lower):
                matched = True
            lower = (operator, bound, bound_suffix)
        elif operator in ('<', '<='):
            if (lower is None or holds(*lower)) and holds(operator, bound, bound_suffix):
                matched = True
            lower = None
        elif holds(operator, bound, bound_suffix):
            matched = True
    if lower is not None and holds(*lower):
        matched = True
    return True if matched else None if uncertain else False

# --- matching devices

STOP_WORDS = {'inc', 'llc', 'ltd', 'co', 'corp', 'corporation', 'company', 'gmbh', 'ag', 'sa', 'se', 'the', 'kg', 'bv', 'plc'}
VENDOR_ALIASES = {'allen': 'rockwell', 'allenbradley': 'rockwell', 'general': 'ge', 'jci': 'johnson', 'telemecanique': 'schneider',
                  'modicon': 'schneider', 'square': 'schneider', 'invensys': 'schneider', 'mitsubishielectric': 'mitsubishi'}

def vendor_keys(name):
    """The companies a vendor name stands for, as short keys: 'Rockwell Automation/Allen-Bradley' -> {'rockwell'}."""
    keys = set()
    for part in re.split(r'[/,&;]|\band\b', str(name or '').lower()):
        words = [w for w in re.findall(r'[a-z0-9]+', part.replace('-', '')) if w not in STOP_WORDS]
        if words:
            keys.add(VENDOR_ALIASES.get(words[0], words[0]))
    return keys

def _tokens(text):
    """Letters and numbers apart, so 'IM151-8 PN/DP' and 'IM 151-8 PN/DP' read the same: ' IM 151 8 PN DP '."""
    return f" {' '.join(re.findall(r'[A-Z]+|\d+', str(text).upper()))} "

def _normal_model(text):
    return re.sub(r'[\s\-_./]', '', str(text).upper())

def _model_pattern(model):
    """A regex for an advisory's model number, where *, ? and a lower-case x are wildcards (BMEP58*S, P14x)."""
    pattern = ''.join('.*' if c == '*' else '.' if c in '?x' else re.escape(c.upper())
                      for c in re.sub(r'[\s\-_./]', '', model))
    return re.compile(pattern + '$')

# Product families an order or catalog number belongs to, for advisories that only name the family
FAMILIES = [
    (re.compile(r'^6(?:ES7|AG\d)21'), 'S7-1200'), (re.compile(r'^6(?:ES7|AG\d)31'), 'S7-300'),
    (re.compile(r'^6(?:ES7|AG\d)41'), 'S7-400'), (re.compile(r'^6(?:ES7|AG\d)51'), 'S7-1500'),
    (re.compile(r'^1756L6'), 'ControlLogix 5560'), (re.compile(r'^1756L7'), 'ControlLogix 5570'),
    (re.compile(r'^1756L8'), 'ControlLogix 5580'), (re.compile(r'^1769L3\dE'), 'CompactLogix 5370'),
    (re.compile(r'^5069L3'), 'CompactLogix 5380'), (re.compile(r'^1766L'), 'MicroLogix 1400'),
    (re.compile(r'^1763L'), 'MicroLogix 1100'), (re.compile(r'^1762L'), 'MicroLogix 1200'),
    (re.compile(r'^1764'), 'MicroLogix 1500'), (re.compile(r'^1761L'), 'MicroLogix 1000'),
    (re.compile(r'^2080L'), 'Micro800'),
]
MATCH_QUALITY = ('model number', 'product name', 'product family')
# A family limited to one firmware generation: 'S7-1200 CPU V4 family', 'CPU family version 4' (not '< V4.x')
GENERATION = re.compile(r'(?i)(?<![<>])(?<![<>] )\bV(\d+)(?:\.x)? family|\bfamily version (\d+)\b|\bfamily V(\d+)\.x\b')

class Index:
    """Imported advisory products, by vendor key and by exact model number."""
    def __init__(self, conn):
        self.advisories = {row['id']: dict(row) for row in conn.execute(
            "SELECT id, title, publisher, url, released, updated, score FROM advisories")}
        self.by_vendor, self.by_model, self.wildcards = defaultdict(list), defaultdict(list), []
        for row in conn.execute("SELECT * FROM advisory_products"):
            product = dict(row)
            product['tokens'] = _tokens(product['product'])
            generation = GENERATION.search(product['product'])
            product['generation'] = int(next(g for g in generation.groups() if g)) if generation else None
            product['range'] = parse_range(product['versions'])
            product['vendor_keys'] = vendor_keys(product['vendor'])
            product['model_ids'], product['patterns'] = set(), []
            for model in (product['models'] or '').split():
                if re.search(r'[*?x]', model):
                    product['patterns'].append(_model_pattern(model))
                elif _normal_model(model):
                    product['model_ids'].add(_normal_model(model))
                    self.by_model[_normal_model(model)].append(product)
            if product['patterns']:
                self.wildcards.append(product)
            for key in product['vendor_keys']:
                self.by_vendor[key].append(product)

_cache = {}

def _index(conn):
    path = conn.execute("PRAGMA database_list").fetchone()['file']
    row = conn.execute("SELECT value FROM settings WHERE key = 'advisories_revision'").fetchone()
    revision = row['value'] if row else '0'
    cached = _cache.get(path)
    if cached is None or cached[0] != revision or not path:
        cached = _cache[path] = (revision, Index(conn))
    return cached[1]

def describe(host):
    """
    What to match for a host: the device itself and any modules it reported (a ControlLogix chassis lists
    its cards), each as a dict of vendor keys, names, order numbers, firmware and families.
    """
    properties = host['properties']
    values = lambda name: properties.get(name, {}).get('values', [])
    vendors = set().union(*(vendor_keys(v) for v in values('Vendor'))) or vendor_keys(host.get('vendor'))
    names = list(dict.fromkeys(values('Model') + values('Product') + values('Platform')))
    orders = list(dict.fromkeys(values('OrderNumber') + [m for text in names + values('SystemDescription')
                                                         for m in ORDER_NUMBER.findall(text)]))
    firmware = values('Firmware') or [v for v in values('Software') if parse_version(v)]
    devices = [_descriptor(None, vendors, names, orders, firmware, host)] if names or orders else []
    for module in values('Module'):
        match = re.match(r'slot (\d+): (.*?)(?: \(firmware ([^)]*)\))?$', module)
        if match and not (match[2] in names and (match[3] in firmware or not match[3])):  # not the module that answered
            devices.append(_descriptor(f'slot {match[1]}', vendors, [match[2]], ORDER_NUMBER.findall(match[2]),
                                       [match[3]] if match[3] else [], host))
    return devices

def _descriptor(slot, vendors, names, orders, firmware, host):
    # Rockwell product names end in the series and firmware revision (1766-L32BWAA B/15.00), which is the
    # controller's firmware; the EtherNet/IP revision may be that of its network interface
    revisions = [m[1] for m in (re.search(r'\s[A-Z]/(\d+(?:\.\d+)*)$', name) for name in names) if m]
    firmware = revisions or firmware
    variants = []
    for name in names:
        variants.append(name)
        trimmed = re.sub(r'\s+[A-Z]/[\d.]+$|/[A-Z]$', '', name)  # series and revision: 1756-ENBT/A, 1766-L32BWAA B/15.00
        if trimmed != name:
            variants.append(trimmed)
    needles = []
    for variant in variants:
        tokens = _tokens(variant)
        if len(tokens.split()) >= 2 and re.search(r'\d', tokens) and tokens not in needles:
            needles.append(tokens)
    identifiers = {_normal_model(v) for v in orders + variants} - {''}
    families = {family for identifier in identifiers for pattern, family in FAMILIES if pattern.match(identifier)}
    return {'slot': slot, 'vendors': vendors, 'names': names, 'orders': orders, 'firmware': firmware,
            'needles': needles, 'identifiers': identifiers, 'has_order': bool(orders),
            'families': [_tokens(f) for f in sorted(families)],
            'generations': {version[0][0] for version in map(parse_version, firmware) if version},
            'vendor': ', '.join(host['properties'].get('Vendor', {}).get('values', [])) or host.get('vendor'),
            'model': ', '.join(names or orders), 'firmware_text': ', '.join(firmware)}

def _match_product(device, product):
    """The quality of the match between a device and an advisory product, or None."""
    same_vendor = bool(device['vendors'] & product['vendor_keys'])
    if product['models']:
        matched = (product['model_ids'] & device['identifiers']) | {i for i in device['identifiers']
                                                                   if any(p.match(i) for p in product['patterns'])}
        # A short number could be anyone's; without the device's vendor, only a long one is trusted
        if matched and (same_vendor or not device['vendors'] and max(map(len, matched)) >= 8):
            return 'model number'
    if not same_vendor:
        return None
    if product['models'] and device['has_order']:
        return None  # the advisory lists the affected order numbers, and the device's isn't one of them
    if product['generation'] is not None and device['generations'] and product['generation'] not in device['generations']:
        return None
    if any(needle in product['tokens'] for needle in device['needles']):
        return 'product name'
    if not product['models'] and any(family in product['tokens'] for family in device['families']):
        return 'product family'
    return None

def _check_versions(device, product):
    """('affected' or 'possible', why), or None if the device's firmware isn't affected."""
    if product['range'] == ALL_VERSIONS:
        return 'affected', 'all versions are affected'
    if not device['firmware']:
        return 'possible', f"affects {product['versions']}; the device's firmware wasn't seen"
    results = [(firmware, in_range(product['range'], firmware)) for firmware in device['firmware']]
    hit = next((f for f, result in results if result), None)
    if hit:
        return 'affected', f"firmware {hit} is in {product['versions']}"
    unsure = next((f for f, result in results if result is None), None)
    if unsure:
        return 'possible', f"affects {product['versions']}; pyLot can't tell whether firmware {unsure} is"
    return None

def severity(score):
    if score is None:
        return 'unknown'
    return 'critical' if score >= 9 else 'high' if score >= 7 else 'medium' if score >= 4 else 'low'

STATUS_ORDER = ('affected', 'possible')

def match_hosts(conn, hosts):
    """Every advisory that may concern each host, most severe first: a list of vulnerability dicts."""
    index = _index(conn)
    if not index.advisories:
        return []
    found = {}
    for host in hosts:
        for device in describe(host):
            candidates = {id(p): p for key in device['vendors'] for p in index.by_vendor.get(key, ())}
            for identifier in device['identifiers']:
                candidates.update((id(p), p) for p in index.by_model.get(identifier, ()))
            candidates.update((id(p), p) for p in index.wildcards)
            for product in candidates.values():
                quality = _match_product(device, product)
                if quality is None:
                    continue
                checked = _check_versions(device, product)
                if checked is None:
                    continue
                status, reason = checked
                key = (host['ip'], device['slot'], product['advisory_id'])
                rank = (MATCH_QUALITY.index(quality), STATUS_ORDER.index(status), -(product['score'] or 0))
                current = found.get(key)
                if current is None:
                    advisory = index.advisories[product['advisory_id']]
                    current = found[key] = {
                        'ip': host['ip'], 'module': device['slot'], 'vendor': device['vendor'], 'model': device['model'],
                        'firmware': device['firmware_text'], 'advisory': advisory['id'], 'title': advisory['title'],
                        'publisher': advisory['publisher'], 'url': advisory['url'], 'released': advisory['released'],
                        'cves': set(), 'score': None, 'rank': None}
                current['cves'].update(c for c in product['cves'].split(', ') if c)
                current['score'] = max(current['score'] or 0, product['score'] or 0) or current['score']
                if current['rank'] is None or rank < current['rank']:
                    current.update(rank=rank, match=quality, status=status, reason=reason, product=product['product'],
                                   product_vendor=product['vendor'], versions=product['versions'], fix=product['fix'])
    results = []
    for item in found.values():
        item.pop('rank')
        score = item['score'] or (index.advisories[item['advisory']]['score'] if not item['cves'] else None)
        results.append({**item, 'cves': sorted(item['cves']), 'score': score, 'severity': severity(score)})
    results.sort(key=lambda v: (STATUS_ORDER.index(v['status']), -(v['score'] or 0), storage._ip_key(v['ip']),
                                v['module'] or '', v['advisory']))
    return results

def session_vulnerabilities(conn, session_id):
    return match_hosts(conn, storage.all_hosts(conn, session_id))

def main(argv=None):
    parser = argparse.ArgumentParser(description='Import security advisories (CSAF) into pyLot.')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('fetch', help="download and import CISA's ICS advisories")
    files = commands.add_parser('import', help='import CSAF files, or .zip or .tar.gz archives of them')
    files.add_argument('files', nargs='+')
    commands.add_parser('status', help='show what has been imported')
    args = parser.parse_args(argv)
    db_path = os.environ.get('PYLOT_DB_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pylot.sqlite3'))
    storage.init_db(db_path)
    conn = storage.connect(db_path)
    try:
        if args.command == 'fetch':
            print(f'Downloading {CISA_ARCHIVE} ...')
            counts = fetch_cisa(conn)
        elif args.command == 'import':
            def documents():
                for path in args.files:
                    with open(path, 'rb') as f:
                        yield from read_documents(path, f.read())
            counts = import_advisories(conn, documents())
        else:
            counts = None
        if counts:
            print(', '.join(f'{n} {what}' for what, n in counts.items()))
        summary = advisory_summary(conn)
        print(f"{summary['advisories']} advisories covering {summary['products']} products; newest {summary['newest']}")
    finally:
        conn.close()

if __name__ == '__main__':
    sys.exit(main())
