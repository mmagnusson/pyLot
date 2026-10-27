import dataclasses
import logging
import os

import pytest

from packet_builder import packet
from parser.fingerprint_loader import Match, load_fingerprints
from parser.fingerprint_matcher import FingerprintEngine, Lookups
from parser.packets import TCP_FLAGS

STOCK = load_fingerprints()
ENGINE = FingerprintEngine(STOCK)

def found(pkt, fingerprint, engine=ENGINE):
    """{ip: merged properties} from one fingerprint's annotations for pkt."""
    merged = {}
    for a in engine.evaluate(pkt):
        if a.fingerprint == fingerprint:
            merged.setdefault(a.ip, {}).update(a.properties)
    return merged

# --- the stock GRASSMARLIN fingerprints

def test_all_stock_fingerprints_load(caplog):
    with caplog.at_level(logging.WARNING):
        assert len(load_fingerprints()) == 118
    assert not caplog.records

@pytest.mark.skipif('PYLOT_GM_FINGERPRINTS' not in os.environ,
                    reason="set PYLOT_GM_FINGERPRINTS to GRASSMARLIN's GM3/data/fingerprint directory")
def test_yaml_conversions_match_grassmarlin_xml():
    strip = lambda fp: dataclasses.replace(fp, source='')
    originals = {fp.name: strip(fp) for fp in load_fingerprints(os.environ['PYLOT_GM_FINGERPRINTS'])}
    assert {fp.name: strip(fp) for fp in STOCK} == originals

def test_modbus_master_is_not_also_tagged_slave():
    request = packet(src='10.0.0.57', dst='10.0.0.3', src_port=2578, dst_port=502,
                     payload=bytes.fromhex('000100000006010300000001'))
    assert found(request, 'MODBUS') == {'10.0.0.57': {'Role': 'MASTER', 'Category': 'MTU', 'ICSProtocol': 'MODBUS'}}

def test_modbus_slave_reports_unit_id():
    response = packet(src='10.0.0.3', dst='10.0.0.57', src_port=502, dst_port=2578,
                      payload=bytes.fromhex('0001000000050a03020007'))
    assert found(response, 'MODBUS') == {'10.0.0.3': {'Role': 'SLAVE', 'Category': 'ICS_HOST', 'ICSProtocol': 'MODBUS', 'Unit': '0A'}}

def test_dnp3_needs_the_header_bytes():
    master = packet(dst_port=20000, payload=bytes.fromhex('05640ac4010002003a1e'))
    assert found(master, 'DNP3') == {'10.0.0.1': {'Category': 'MTU', 'Role': 'MASTER', 'ICSProtocol': 'DNP3'}}
    assert found(packet(dst_port=20000, payload=b'not dnp3'), 'DNP3') == {}

def test_hex_content_matches_whole_bytes_only():
    # 30 56 4a contains the hex digits '0564' across a byte boundary, which the old matcher accepted
    assert found(packet(dst_port=20000, payload=bytes.fromhex('30564a')), 'DNP3') == {}

def test_operating_system_guess_follows_ttl():
    windows = found(packet(ttl=128), 'Operating System')['10.0.0.1']
    linux = found(packet(ttl=64), 'Operating System')['10.0.0.1']
    assert 'Windows' in windows['OS'] and 'Windows' not in linux['OS']

def test_hex_content_keeps_leading_zero_bytes():
    def contents(ops):
        for op in ops:
            if isinstance(op, Match):
                yield op.content
                yield from contents(op.and_then)
    dcerpc = next(fp for fp in STOCK if fp.name == 'DCERPC')
    assert bytes.fromhex('00000100C4') in [c for p in dcerpc.payloads for c in contents(p.operations)]

# --- engine semantics, with small fingerprints written as GRASSMARLIN XML

RETURN = '<Return Confidence="2"><Details><Category>{}</Category></Details>{}</Return>'

def ret(category='PLC', extracts=''):
    return RETURN.format(category, extracts)

def engine_for(tmp_path, payloads, filters='<Filter For="p"><DstPort>9999</DstPort></Filter>'):
    (tmp_path / 'test.xml').write_text(f'<Fingerprint><Header><Name>T</Name></Header>{filters}{payloads}</Fingerprint>')
    return FingerprintEngine(load_fingerprints(str(tmp_path)), Lookups(str(tmp_path)))

def run(engine, payload=b'', **kwargs):
    return found(packet(dst_port=kwargs.pop('dst_port', 9999), payload=payload, **kwargs), 'T', engine).get(kwargs.get('src', '10.0.0.1'), {})

def one_payload(tmp_path, body, **kwargs):
    return engine_for(tmp_path, f'<Payload For="p">{body}</Payload>', **kwargs)

def test_payload_runs_only_for_its_filter_group(tmp_path):
    engine = engine_for(tmp_path, f'<Payload For="a">{ret("PLC")}</Payload><Payload For="b">{ret("HMI")}</Payload>',
                        filters='<Filter For="a"><DstPort>1</DstPort></Filter><Filter For="b"><DstPort>2</DstPort></Filter>')
    assert run(engine, dst_port=1) == {'Category': 'PLC'}
    assert run(engine, dst_port=2) == {'Category': 'HMI'}

def test_payload_runs_once_when_several_groups_match(tmp_path):
    engine = engine_for(tmp_path, f'<Payload For="p">{ret()}</Payload>',
                        filters='<Filter For="p"><DstPort>9999</DstPort></Filter><Filter For="p"><TransportProtocol>6</TransportProtocol></Filter>')
    assert len(engine.evaluate(packet(dst_port=9999))) == 1

def test_always_fires_without_payload_but_operations_do_not(tmp_path):
    engine = one_payload(tmp_path, f'<Always><Return Confidence="3"><Details><Role>SERVER</Role></Details></Return></Always>'
                                   f'<Match><Content Type="HEX">01</Content><AndThen>{ret()}</AndThen></Match>')
    assert run(engine) == {'Role': 'SERVER'}
    assert run(engine, b'\x01') == {'Role': 'SERVER', 'Category': 'PLC'}

@pytest.mark.parametrize('attrs, payload, matches', [
    ('', b'\x00\x00\x01', True),                     # the last payload byte is searchable
    ('Offset="2" Depth="4"', b'\x00' * 5 + b'\x01', True),
    ('Offset="2" Depth="3"', b'\x00' * 5 + b'\x01', False),
    ('Offset="9"', b'\x01', False),
])
def test_match_window(tmp_path, attrs, payload, matches):
    engine = one_payload(tmp_path, f'<Match {attrs}><Content Type="HEX">01</Content><AndThen>{ret()}</AndThen></Match>')
    assert bool(run(engine, payload)) == matches

def test_relative_match_starts_at_previous_match(tmp_path):
    engine = one_payload(tmp_path, '<Match><Content Type="STRING">AB</Content><AndThen>'
                                   f'<Match Relative="true" Offset="2"><Content Type="STRING">CD</Content><AndThen>{ret()}</AndThen></Match>'
                                   '</AndThen></Match>')
    assert run(engine, b'xxABCD')
    assert not run(engine, b'CDxxAB')

def test_no_case_applies_to_content(tmp_path):
    engine = one_payload(tmp_path, f'<Match NoCase="true"><Content Type="STRING">hello</Content><AndThen>{ret()}</AndThen></Match>')
    assert run(engine, b'say HeLLo')
    strict = one_payload(tmp_path, f'<Match><Content Type="STRING">hello</Content><AndThen>{ret()}</AndThen></Match>')
    assert not run(strict, b'say HeLLo')

def test_pattern_search_and_cursor_extract(tmp_path):
    extract = '<Extract Name="Device" From="CURSOR_START" To="CURSOR_END"><Post Convert="STRING"/></Extract>'
    engine = one_payload(tmp_path, f'<Match><Pattern>Name=[A-Za-z]+</Pattern><AndThen>{ret(extracts=extract)}</AndThen></Match>')
    assert run(engine, b'\x00\x01Name=Pump;') == {'Category': 'PLC', 'Device': 'Name=Pump'}

def test_anchor_moves_cursors_for_extract(tmp_path):
    extract = '<Extract Name="Tag" From="CURSOR_START" To="CURSOR_END"><Post Convert="STRING"/></Extract>'
    engine = one_payload(tmp_path, '<Match><Content Type="STRING">ID:</Content><AndThen>'
                                   '<Anchor Cursor="START" Position="CURSOR_END"/><Anchor Cursor="END" Position="END_OF_PAYLOAD"/>'
                                   f'{ret(extracts=extract)}</AndThen></Match>')
    assert run(engine, b'ID:PLC-7')['Tag'] == 'PLC-7'

@pytest.mark.parametrize('op, payload, passes', [
    ('<GT>5</GT>', b'\x06', True),
    ('<GT>5</GT>', b'\x05', False),
    ('<EQ>258</EQ>', b'\x02\x01', True),
])
def test_byte_test(tmp_path, op, payload, passes):
    endian = 'Bytes="2" Endian="LITTLE"' if len(payload) == 2 else ''
    engine = one_payload(tmp_path, f'<ByteTest {endian}>{op}<AndThen>{ret()}</AndThen></ByteTest>')
    assert bool(run(engine, payload)) == passes

def test_byte_test_past_the_end_fails(tmp_path):
    # GRASSMARLIN read 0 here, so LT would have passed
    engine = one_payload(tmp_path, f'<ByteTest Offset="10"><LT>5</LT><AndThen>{ret()}</AndThen></ByteTest>')
    assert not run(engine, b'\x01')

def test_is_data_at(tmp_path):
    engine = one_payload(tmp_path, f'<IsDataAt Offset="3"><AndThen>{ret()}</AndThen></IsDataAt>')
    assert run(engine, b'1234') and not run(engine, b'123')

def test_byte_jump_moves_main_cursor(tmp_path):
    later = f'<Match Relative="true"><Content Type="HEX">FF</Content><AndThen>{ret()}</AndThen></Match>'
    engine = one_payload(tmp_path, f'<ByteJump Bytes="1"><AndThen>{later}</AndThen></ByteJump>')
    assert run(engine, b'\x03\x00\x00\xff')
    assert not run(engine, b'\x03\xff\x00\x00')  # the FF before the jump target isn't searched

def test_byte_jump_calc(tmp_path):
    later = f'<Match Relative="true" Depth="1"><Content Type="HEX">FF</Content><AndThen>{ret()}</AndThen></Match>'
    engine = one_payload(tmp_path, f'<ByteJump Bytes="1"><Calc>x*2+1</Calc><AndThen>{later}</AndThen></ByteJump>')
    assert run(engine, b'\x02\x00\x00\x00\x00\xff')

@pytest.mark.parametrize('extract, expected', [
    ('<Extract Name="V" From="0" To="2"><Post Convert="INTEGER"/></Extract>', '256'),
    ('<Extract Name="V" From="0" To="2" Endian="LITTLE"><Post Convert="INTEGER"/></Extract>', '1'),
    ('<Extract Name="V" From="0" To="2"/>', '0100'),
    ('<Extract Name="V" From="0" To="END_OF_PAYLOAD"><Post Convert="RAW_BYTES"/></Extract>', '[1, 0, -1]'),
])
def test_extract_conversions(tmp_path, extract, expected):
    engine = one_payload(tmp_path, f'<Always>{ret(extracts=extract)}</Always>')
    assert run(engine, b'\x01\x00\xff')['V'] == expected

def test_extract_lookup_uses_reference_table_or_reports_the_id(tmp_path):
    extract = '<Extract Name="Vendor" From="0" To="2" Endian="LITTLE"><Post Lookup="ENIPVENDOR"/></Extract>'
    engine = one_payload(tmp_path, f'<Always>{ret(extracts=extract)}</Always>')
    assert run(engine, b'\x01\x00')['Vendor'] == '1'
    (tmp_path / 'ENIPVENDOR.csv').write_text('1,Rockwell Automation/Allen-Bradley\n')
    engine = one_payload(tmp_path, f'<Always>{ret(extracts=extract)}</Always>')
    assert run(engine, b'\x01\x00')['Vendor'] == 'Rockwell Automation/Allen-Bradley'

def test_destination_direction(tmp_path):
    engine = one_payload(tmp_path, '<Always><Return Direction="DESTINATION" Confidence="1"><Details><Role>SERVER</Role></Details></Return></Always>')
    [annotation] = engine.evaluate(packet(src='10.0.0.1', dst='10.0.0.2', dst_port=9999))
    assert annotation.ip == '10.0.0.2' and annotation.confidence == 1

def test_flags_filter_needs_every_flag(tmp_path):
    engine = engine_for(tmp_path, f'<Payload For="p">{ret()}</Payload>', filters='<Filter For="p"><Flags>SYN ACK</Flags></Filter>')
    assert run(engine, tcp_flags=TCP_FLAGS['SYN'] | TCP_FLAGS['ACK'])
    assert not run(engine, tcp_flags=TCP_FLAGS['SYN'])
    assert not run(engine, transport=17)
