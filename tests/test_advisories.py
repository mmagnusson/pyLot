import io
import json
import tarfile
import zipfile

import pytest

import advisories
import storage

def csaf(tracking_id, products, cves=(('CVE-2024-0001', 7.5),), updated='2024-01-04T00:00:00Z', title='Test advisory'):
    """A minimal CSAF 2.0 advisory: products are (vendor, product name, version or None, model numbers)."""
    branches, ids = {}, []
    for n, (vendor, name, version, models) in enumerate(products, 1):
        pid = f'CSAFPID-{n:04}'
        ids.append(pid)
        product = {'name': f'{vendor} {name}', 'product_id': pid}
        if models:
            product['product_identification_helper'] = {'model_numbers': list(models)}
        leaf = ({'category': 'product_version_range', 'name': version, 'product': product} if version
                else None)
        name_branch = {'category': 'product_name', 'name': name}
        if leaf:
            name_branch['branches'] = [leaf]
        else:
            name_branch['product'] = product
        branches.setdefault(vendor, []).append(name_branch)
    return {
        'document': {'category': 'csaf_security_advisory', 'csaf_version': '2.0', 'title': title,
                     'publisher': {'name': 'CISA', 'category': 'coordinator'},
                     'tracking': {'id': tracking_id, 'initial_release_date': '2024-01-04T00:00:00Z', 'current_release_date': updated}},
        'product_tree': {'branches': [{'category': 'vendor', 'name': v, 'branches': b} for v, b in branches.items()]},
        'vulnerabilities': [{'cve': cve, 'product_status': {'known_affected': ids},
                             'scores': [{'cvss_v3': {'baseScore': score}, 'products': ids}],
                             'remediations': [{'category': 'vendor_fix', 'details': 'Update to the latest firmware.', 'product_ids': ids}]}
                            for cve, score in cves]}

def host(ip, vendor=None, mac_vendor=None, **properties):
    names = {'model': 'Model', 'product': 'Product', 'order': 'OrderNumber', 'firmware': 'Firmware', 'module': 'Module'}
    props = {names[k]: {'confidence': 1, 'values': v if isinstance(v, list) else [v]} for k, v in properties.items()}
    if vendor:
        props['Vendor'] = {'confidence': 1, 'values': [vendor]}
    return {'ip': ip, 'vendor': mac_vendor, 'properties': props}

@pytest.fixture
def conn(tmp_path):
    path = str(tmp_path / 'advisories.sqlite3')
    storage.init_db(path)
    connection = storage.connect(path)
    yield connection
    connection.close()

def load(conn, *documents):
    return advisories.import_advisories(conn, [(f'{n}.json', d) for n, d in enumerate(documents)])

def found(conn, *hosts):
    return [(v['ip'], v['module'], v['advisory'], v['status'], v['match']) for v in advisories.match_hosts(conn, list(hosts))]

@pytest.mark.parametrize('versions, firmware, expected', [
    ('vers:intdot/<4.5.0', 'V4.4.1', True), ('vers:intdot/<4.5.0', '4.5', False), ('<V4.0', 'V1.0.1', True),
    ('<= 5.008', '4.007', True), ('<= 5.008', '5.028', False), ('vers:all/*', 'anything', True), (None, '1.0', True),
    ('vers:intdot/>=7.80|<8.90', '8.1', True), ('vers:intdot/>=7.80|<8.90', '9.0', False), ('vers:intdot/>=7.80|<8.90', '7.5', False),
    ('<4.0|>=5.0|<5.3', '5.1', True), ('<4.0|>=5.0|<5.3', '4.5', False), ('>=V2.0.0_<V2.1', 'V2.0.5', True),
    ('2.X|3.X', 'V3.2.6', True), ('2.X|3.X', '4.1', False), ('V6.006', '6.6', True), ('V6.006', '6.7', False),
    ('2.3 and prior', '2.1', True), ('2.3 and prior', '2.4', False), ('4.0 and later', '4.2', True),
    ('<V18_Update_2', 'V17', True), ('<V18_Update_2', 'V18', None), ('<V5.6_SP1_HF7', 'V5.6', None),
    ('<_with_Function_State_FS_11', '4.1', None), ('<= 9.9', 'not a version', None),
])
def test_affected_versions(versions, firmware, expected):
    assert advisories.in_range(advisories.parse_range(versions), firmware) is expected

def test_vendor_names_reduce_to_the_company():
    assert advisories.vendor_keys('Rockwell Automation/Allen-Bradley') == {'rockwell'}
    assert advisories.vendor_keys('Schneider Electric Software, LLC') == {'schneider'}
    assert advisories.vendor_keys('General Electric (GE)') == {'ge'} == advisories.vendor_keys('GE')
    assert advisories.vendor_keys('Alerton / Honeywell') == {'alerton', 'honeywell'}
    assert advisories.vendor_keys('Siemens AG') == {'siemens'}

def test_devices_match_by_order_number_name_and_family(conn):
    load(conn,
         csaf('ICSA-1', [('Siemens', 'SIMATIC S7-300 CPU 315-2 PN/DP (6ES7315-2EH14-0AB0)', '<V3.2.16', ())]),
         csaf('ICSA-2', [('Rockwell Automation', '1756-ENBT', 'vers:all/*', ())]),
         csaf('ICSA-3', [('Siemens', 'SIMATIC S7-1200 CPU family (incl. SIPLUS variants)', '<V4.5.0', ())]),
         csaf('ICSA-4', [('Siemens', 'SIMATIC S7-1200 CPU 1212C DC/DC/DC', 'vers:intdot/<4.5.0', ('6ES7212-1AE40-0XB0',))]),
         csaf('ICSA-5', [('Siemens', 'SIMATIC S7-1200 CPU V4 family', '<V4.5.0', ())]),
         csaf('ICSA-6', [('Rockwell Automation', '1756-ENBT', '<= 3.0', ())]))
    s7_300 = host('10.0.0.1', 'Siemens', model='CPU 315-2 PN/DP', order='6ES7 315-2EH14-0AB0', firmware='V3.2.7')
    enbt = host('10.0.0.2', 'Rockwell Automation/Allen-Bradley', product='1756-ENBT/A', firmware='4.003')
    s7_1200 = host('10.0.0.3', 'Siemens', order='6ES7 212-1BD30-0XB0', firmware='V1.0.1')
    assert found(conn, s7_300, enbt, s7_1200) == [
        ('10.0.0.1', None, 'ICSA-1', 'affected', 'model number'),
        ('10.0.0.2', None, 'ICSA-2', 'affected', 'product name'),
        ('10.0.0.3', None, 'ICSA-3', 'affected', 'product family')]
    # ICSA-4 lists the order numbers it covers; ICSA-5 is for V4 CPUs; ICSA-6 is for older firmware

def test_firmware_decides_affected_or_possibly(conn):
    load(conn, csaf('ICSA-1', [('Siemens', 'SIMATIC S7-300 CPU 315-2 PN/DP (6ES7315-2EH14-0AB0)', '<V3.2.16', ())]))
    order = '6ES7 315-2EH14-0AB0'
    assert found(conn, host('10.0.0.1', 'Siemens', order=order, firmware='V3.2.16')) == []
    assert found(conn, host('10.0.0.1', 'Siemens', order=order)) == [('10.0.0.1', None, 'ICSA-1', 'possible', 'model number')]
    [match] = advisories.match_hosts(conn, [host('10.0.0.1', 'Siemens', order=order, firmware=['V3.2.20', 'V3.2.6'])])
    assert (match['status'], match['reason']) == ('affected', 'firmware V3.2.6 is in <V3.2.16')
    assert (match['cves'], match['score'], match['severity'], match['fix']) == (['CVE-2024-0001'], 7.5, 'high', 'Update to the latest firmware.')
    assert match['url'] is None  # not a CISA id, and no link of its own

def test_vendor_must_agree_unless_the_model_number_does(conn):
    load(conn, csaf('ICSA-1', [('Rockwell Automation', '1756-ENBT', None, ())]),
         csaf('ICSA-2', [('Schneider Electric', 'Modicon M580', None, ('BMEP58*S',))]))
    assert found(conn, host('10.0.0.1', 'Somebody Else', product='1756-ENBT/A')) == []
    assert found(conn, host('10.0.0.2', product='1756-ENBT/A', mac_vendor='Rockwell Automation')) == [
        ('10.0.0.2', None, 'ICSA-1', 'affected', 'product name')]
    assert found(conn, host('10.0.0.3', product='BMEP582040S')) == [('10.0.0.3', None, 'ICSA-2', 'affected', 'model number')]
    assert found(conn, host('10.0.0.4', 'Siemens', product='BMEP582040S')) == []

def test_short_model_numbers_need_the_vendor(conn):
    load(conn, csaf('ICSA-1', [('Baxter', 'Pump', None, ('4110',))]))
    assert found(conn, host('10.0.0.1', 'Siemens', model='4110 X')) == []
    assert found(conn, host('10.0.0.1', model='4110')) == []
    assert found(conn, host('10.0.0.1', 'Baxter International', model='4110')) == [('10.0.0.1', None, 'ICSA-1', 'affected', 'model number')]

def test_modules_in_a_chassis_are_matched_with_their_own_firmware(conn):
    load(conn, csaf('ICSA-1', [('Rockwell Automation', 'ControlLogix 5560 controllers', '<= 20.0', ())]),
         csaf('ICSA-2', [('Rockwell Automation', '1756-ENBT', '<= 4.005', ())]))
    chassis = host('10.0.0.1', 'Rockwell Automation/Allen-Bradley', product='1756-ENBT/A', firmware='4.007',
                   module=['slot 0: 1756-L61/B LOGIX5561 (firmware 16.020)', 'slot 1: 1756-ENBT/A (firmware 4.003)'])
    assert found(conn, chassis) == [('10.0.0.1', 'slot 0', 'ICSA-1', 'affected', 'product family'),
                                    ('10.0.0.1', 'slot 1', 'ICSA-2', 'affected', 'product name')]
    # The card that answered lists itself among the modules: it's the host, not another device
    chassis['properties']['Firmware']['values'] = ['4.003']
    assert found(conn, chassis) == [('10.0.0.1', None, 'ICSA-2', 'affected', 'product name'),
                                    ('10.0.0.1', 'slot 0', 'ICSA-1', 'affected', 'product family')]

def test_rockwell_revision_in_the_product_name_is_the_firmware(conn):
    load(conn, csaf('ICSA-1', [('Rockwell Automation', 'MicroLogix 1400 Controllers Series B', '<= 15.002', ())]))
    [match] = advisories.match_hosts(conn, [host('10.0.0.1', 'Rockwell Automation/Allen-Bradley', product='1766-L32BWAA B/15.00',
                                                 firmware='2.015')])
    assert (match['match'], match['reason']) == ('product family', 'firmware 15.00 is in <= 15.002')

def test_imports_replace_older_revisions_and_skip_other_files(conn):
    first = csaf('ICSA-24-004-01', [('Rockwell Automation', '1756-ENBT', None, ())])
    assert load(conn, first, {'not': 'csaf'}, None) == {'added': 1, 'updated': 0, 'unchanged': 0, 'skipped': 2}
    assert load(conn, first) == {'added': 0, 'updated': 0, 'unchanged': 1, 'skipped': 0}
    enbt = host('10.0.0.1', 'Rockwell Automation', product='1756-ENBT/A', firmware='4.003')
    assert len(found(conn, enbt)) == 1
    fixed = csaf('ICSA-24-004-01', [('Rockwell Automation', '1756-ENBT', '<= 3.0', ())], updated='2024-02-01T00:00:00Z')
    assert load(conn, fixed) == {'added': 0, 'updated': 1, 'unchanged': 0, 'skipped': 0}
    assert found(conn, enbt) == []  # the matcher saw the new revision
    summary = advisories.advisory_summary(conn)
    assert (summary['advisories'], summary['products'], summary['publishers']) == (1, 1, [{'publisher': 'CISA', 'advisories': 1}])
    row = conn.execute("SELECT url FROM advisories").fetchone()
    assert row['url'] == 'https://www.cisa.gov/news-events/ics-advisories/icsa-24-004-01'
    advisories.delete_advisories(conn)
    assert found(conn, enbt) == [] and advisories.advisory_summary(conn)['advisories'] == 0

def test_advisories_are_read_from_archives():
    one, two = csaf('ICSA-1', [('Siemens', 'X 100', None, ())]), csaf('ICSA-2', [('Siemens', 'X 200', None, ())])
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, 'w') as archive:
        archive.writestr('a/icsa-1.json', json.dumps(one))
        archive.writestr('a/readme.txt', 'not json')
    tarred = io.BytesIO()
    with tarfile.open(fileobj=tarred, mode='w:gz') as archive:
        for name, document in (('OT/icsa-2.json', two), ('OT/broken.json', None)):
            data = json.dumps(document).encode() if document else b'{'
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    assert [(n, d['document']['tracking']['id']) for n, d in advisories.read_documents('x.zip', zipped.getvalue())] == [('a/icsa-1.json', 'ICSA-1')]
    assert [(n, d and d['document']['tracking']['id']) for n, d in advisories.read_documents('x.tgz', tarred.getvalue())] == [
        ('OT/icsa-2.json', 'ICSA-2'), ('OT/broken.json', None)]
    assert [n for n, _ in advisories.read_documents('one.json', json.dumps(one).encode())] == ['one.json']

def test_fetching_from_cisa_imports_only_industrial_advisories(conn, monkeypatch):
    tarred = io.BytesIO()
    with tarfile.open(fileobj=tarred, mode='w:gz') as archive:
        for name, document in (('CSAF-develop/csaf_files/OT/white/2024/icsa-1.json', csaf('ICSA-1', [('Siemens', 'X 100', None, ())])),
                               ('CSAF-develop/csaf_files/IT/white/2024/va-1.json', csaf('VA-1', [('Microsoft', 'Y 1', None, ())]))):
            data = json.dumps(document).encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False
    monkeypatch.setattr(advisories.urllib.request, 'urlopen', lambda request, timeout: Response(tarred.getvalue()))
    assert advisories.fetch_cisa(conn) == {'added': 1, 'updated': 0, 'unchanged': 0, 'skipped': 0}
    assert [r['id'] for r in conn.execute("SELECT id FROM advisories")] == ['ICSA-1']
