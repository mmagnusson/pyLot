import struct

from packet_builder import (bacnet_i_am, bacnet_read_property_ack, cip_identity, cip_path, dnp3_frame, enip, enip_list_identity_reply,
                            enip_send_rr, iec104_apdu, modbus_adu, modbus_device_identification, packet, s7_job, s7_read_var,
                            s7_szl_reply, s7_userdata, snmp_get_response, szl_component_entry, szl_module_entry, tpkt)
from parser.ics import Decoder

CLIENT, SERVER = '10.0.0.5', '10.0.0.20'

def request(port, payload, transport=6, **kwargs):
    return packet(src=CLIENT, dst=SERVER, transport=transport, src_port=50000, dst_port=port, payload=payload, **kwargs)

def reply(port, payload, transport=6, **kwargs):
    return packet(src=SERVER, dst=CLIENT, transport=transport, src_port=port, dst_port=50000, payload=payload, **kwargs)

def decode(*packets):
    decoder, operations, facts = Decoder(), [], []
    for pkt in packets:
        o, f = decoder.decode(pkt)
        operations += o
        facts += f
    return operations, facts

def names(operations):
    return [(name, kind) for _, _, _, name, kind in operations]

def properties(facts, ip):
    return {(name, value) for fact_ip, _, name, value, _ in facts if fact_ip == ip}

# --- Modbus

def test_modbus_requests_become_operations_and_roles():
    operations, facts = decode(request(502, modbus_adu(6, b'\x00\x01\x00\x2a', unit=3)),
                               request(502, modbus_adu(3, b'\x00\x00\x00\x0a')))
    assert names(operations) == [('Write Single Register', 'write'), ('Read Holding Registers', 'read')]
    assert operations[0][:3] == (CLIENT, SERVER, 'Modbus')
    assert {('Role', 'MASTER'), ('ICSProtocol', 'MODBUS')} <= properties(facts, CLIENT)
    assert {('Role', 'SLAVE'), ('ModbusUnit', '3')} <= properties(facts, SERVER)
    assert all(confidence == 2 for *_, confidence in facts)

def test_modbus_umas_and_diagnostics_subfunctions():
    operations, _ = decode(request(502, modbus_adu(90, b'\x00\x41')), request(502, modbus_adu(8, b'\x00\x04\x00\x00')))
    assert names(operations) == [('UMAS Stop PLC', 'control'), ('Force Listen Only Mode', 'control')]

def test_modbus_exceptions_and_device_identification():
    operations, facts = decode(reply(502, modbus_adu(0x86, b'\x02')),
                               reply(502, modbus_device_identification({0: 'Schneider Electric', 1: 'BMX P34 2020', 2: 'v2.70'})))
    assert names(operations) == [('Exception to Write Single Register: Illegal Data Address', 'error')]
    assert operations[0][:2] == (CLIENT, SERVER)  # listed under the request's conversation
    identity = {(name, value, confidence) for ip, _, name, value, confidence in facts if ip == SERVER and confidence == 1}
    assert identity == {('Vendor', 'Schneider Electric', 1), ('ProductCode', 'BMX P34 2020', 1), ('Firmware', 'v2.70', 1)}

def test_tcp_reassembly_splits_and_joins_messages():
    two = modbus_adu(1, b'\x00\x00\x00\x08', transaction=1) + modbus_adu(2, b'\x00\x00\x00\x08', transaction=2)
    long = modbus_adu(16, b'\x00\x00\x00\x02\x04\x00\x01\x00\x02', transaction=3)
    segments = [request(502, two, seq=1000), request(502, long[:5], seq=1000 + len(two)),
                request(502, long[5:], seq=1005 + len(two)),
                request(502, long[5:], seq=1005 + len(two))]  # a retransmission
    operations, _ = decode(*segments)
    assert names(operations) == [('Read Coils', 'read'), ('Read Discrete Inputs', 'read'), ('Write Multiple Registers', 'write')]

def test_traffic_on_an_ics_port_that_isnt_the_protocol_is_ignored():
    operations, facts = decode(request(502, b'GET / HTTP/1.1\r\n\r\n'), request(20000, b'\x05\x64\x05\xc4garbage!!'),
                               request(102, b'\x03\x00\x00\x10' + b'\x00' * 12))
    assert operations == [] and facts == []

# --- DNP3

def test_dnp3_functions_roles_and_addresses():
    operations, facts = decode(request(20000, dnp3_frame(5, source=1, destination=10)),
                               reply(20000, dnp3_frame(130, source=10, destination=1, control=0x44)))
    assert names(operations) == [('Direct Operate', 'control'), ('Unsolicited Response', 'data')]
    assert {('Role', 'MASTER'), ('DNP3Address', '1')} <= properties(facts, CLIENT)
    assert {('Role', 'SLAVE'), ('DNP3Address', '10')} <= properties(facts, SERVER)

def test_dnp3_long_fragments_and_bad_crcs():
    frame = dnp3_frame(2, objects=bytes(range(40)))  # user data spans three CRC blocks
    corrupt = bytearray(dnp3_frame(13))
    corrupt[8] ^= 0xFF
    operations, _ = decode(request(20000, frame), request(20000, bytes(corrupt)))
    assert names(operations) == [('Write', 'write')]

# --- S7comm

def test_s7_jobs_with_areas_and_pi_services():
    pi = b'\x28\x00\x00\x00\x00\x00\x00\xfd\x00\x00\x09P_PROGRAM'
    operations, facts = decode(request(102, s7_read_var(area=0x82)), request(102, s7_job(b'\x29' + b'\x00' * 15)),
                               request(102, s7_job(pi)), request(102, s7_job(b'\x1a' + b'\x00' * 17)))
    assert names(operations) == [('Read Var (Outputs)', 'read'), ('PLC Stop', 'control'),
                                 ('PLC Start (PI service P_PROGRAM)', 'control'), ('Request Download', 'program')]
    assert {('Role', 'SLAVE'), ('ICSProtocol', 'S7COMM')} <= properties(facts, SERVER)

def test_s7_download_blocks_requested_by_the_plc_count_as_programming_it():
    operations, _ = decode(reply(102, s7_job(b'\x1b\x00' + b'\x00' * 16)))
    assert names(operations) == [('Download Block', 'program')] and operations[0][:2] == (CLIENT, SERVER)

def test_s7_userdata_requests():
    szl_request = b'\xff\x09\x00\x04\x00\x11\x00\x00'
    operations, _ = decode(request(102, s7_userdata(4, 1, szl_request)), request(102, s7_userdata(7, 2)),
                           request(102, s7_userdata(1, 8)))
    assert names(operations) == [('Read SZL 0x0011 (module identification)', 'diagnostic'), ('Set Clock', 'write'),
                                 ('Modify Variable', 'write')]

def test_s7_module_and_component_identification():
    module = s7_szl_reply(0x0011, [szl_module_entry(1, '6ES7 315-2EH14-0AB0'), szl_module_entry(7, '', b'V\x03\x02\x06')], 28)
    component = s7_szl_reply(0x001C, [szl_component_entry(1, 'Line 4 PLC'), szl_component_entry(5, 'S C-C6TW74882012'),
                                      szl_component_entry(7, 'CPU 315-2 PN/DP')], 34)
    _, facts = decode(reply(102, module), reply(102, component))
    assert {('OrderNumber', '6ES7 315-2EH14-0AB0'), ('Vendor', 'Siemens'), ('Firmware', 'V3.2.6'), ('Name', 'Line 4 PLC'),
            ('Serial', 'S C-C6TW74882012'), ('Model', 'CPU 315-2 PN/DP')} <= properties(facts, SERVER)

def test_s7comm_plus_is_recognised_and_iso_traffic_ignored():
    _, facts = decode(request(102, tpkt(b'\x72\x01\x00\x10' + b'\x00' * 16)), request(102, tpkt(b'\x01\x00\x01\x00')))
    assert ('ICSProtocol', 'S7COMM-PLUS') in properties(facts, SERVER)
    assert not any(value == 'S7COMM' for *_, value, _ in facts)

# --- EtherNet/IP and CIP

def test_list_identity_reply_gives_the_device_identity():
    operations, facts = decode(request(44818, enip(0x63), transport=17), reply(44818, enip_list_identity_reply(), transport=17))
    assert names(operations) == [('List Identity', 'diagnostic')]
    assert {('Vendor', 'Rockwell Automation/Allen-Bradley'), ('DeviceType', 'Programmable Logic Controller'), ('ProductCode', '90'),
            ('Firmware', '20.011'), ('Serial', '0x00ABCDEF'), ('Product', '1756-L71/B LOGIX5571')} <= properties(facts, SERVER)

def test_cip_requests_are_named_and_replies_matched():
    get_identity = bytes([0x01]) + cip_path(0x01)
    write_tag = b'\x4d\x03\x91\x04Tank\x00\x00\xc4\x00\x01\x00\x00\x00\x80\x3f'
    stop = bytes([0x07]) + cip_path(0x8e)
    operations, facts = decode(
        request(44818, enip(0x65, b'\x01\x00\x00\x00')),
        request(44818, enip_send_rr(get_identity, b'ctx-0001')),
        request(44818, enip_send_rr(write_tag, b'ctx-0002')),
        request(44818, enip_send_rr(stop, b'ctx-0003')),
        reply(44818, enip_send_rr(b'\x81\x00\x00\x00' + cip_identity(name='1756-EN2T/D', revision=(11, 2)), b'ctx-0001')),
        reply(44818, enip_send_rr(b'\xcd\x00\x0f\x00', b'ctx-0002')))
    assert names(operations) == [('Register Session', 'session'), ('Get_Attributes_All Identity', 'read'), ('Write Tag', 'write'),
                                 ('Stop class 0x8E', 'control'), ('Error response to Write Tag: privilege violation', 'error')]
    assert {('Product', '1756-EN2T/D'), ('Firmware', '11.002')} <= properties(facts, SERVER)
    assert ('Role', 'CLIENT') in properties(facts, CLIENT)

def test_cip_unconnected_send_through_the_backplane_describes_a_module():
    embedded = bytes([0x01]) + cip_path(0x01)
    send = (bytes([0x52]) + cip_path(0x06) + b'\x0a\xf0' + struct.pack('<H', len(embedded)) + embedded
            + (b'\x00' if len(embedded) % 2 else b'') + b'\x01\x00\x01\x02')  # route: backplane, slot 2
    operations, facts = decode(request(44818, enip_send_rr(send)),
                               reply(44818, enip_send_rr(b'\x81\x00\x00\x00' + cip_identity(name='1756-L61/B LOGIX5561'))))
    assert names(operations) == [('Get_Attributes_All Identity', 'read')]
    assert properties(facts, SERVER) >= {('Module', 'slot 2: 1756-L61/B LOGIX5561 (firmware 20.011)')}
    assert not any(name == 'Product' for _, _, name, _, _ in facts)

# --- IEC 104

def test_iec104_commands_monitor_data_and_addresses():
    operations, facts = decode(request(2404, b'\x68\x04\x07\x00\x00\x00'),  # STARTDT act
                               request(2404, iec104_apdu(45, cause=6, address=7)),
                               reply(2404, iec104_apdu(45, cause=7 | 0x40, address=7)),
                               reply(2404, iec104_apdu(13, cause=3, address=7)),
                               request(2404, iec104_apdu(100, cause=6, address=0xFFFF)))
    assert names(operations) == [('STARTDT act', 'session'), ('C_SC_NA_1 Single command', 'control'),
                                 ('Negative confirmation: C_SC_NA_1 Single command', 'error'),
                                 ('M_ME_NC_1 Measured value, short float', 'data'), ('C_IC_NA_1 Interrogation command', 'read')]
    assert {('IEC104Address', '7'), ('Role', 'SLAVE')} <= properties(facts, SERVER)
    assert ('IEC104Address', '65535') not in properties(facts, SERVER)

# --- BACnet

def test_bacnet_i_am_and_device_properties():
    i_am = packet(src=SERVER, dst='10.0.0.255', transport=17, src_port=47808, dst_port=47808, payload=bacnet_i_am(2401, 5))
    operations, facts = decode(i_am, reply(47808, bacnet_read_property_ack(2401, 70, 'MS-NAE4510-2'), transport=17),
                               reply(47808, bacnet_read_property_ack(2401, 44, '9.0.1'), transport=17))
    assert names(operations) == [('i-Am', 'diagnostic')]
    assert {('DeviceInstance', '2401'), ('Vendor', 'Johnson Controls, Inc.'), ('Model', 'MS-NAE4510-2'),
            ('Firmware', '9.0.1')} <= properties(facts, SERVER)

def test_bacnet_confirmed_requests():
    write = b'\x00\x05\x01\x0f' + b'\x0c\x00\x00\x00\x01\x19\x55\x3e\x44\x42\x28\x00\x00\x3f'
    operations, facts = decode(request(47808, bytes([0x81, 0x0a, 0, 4 + 2 + len(write)]) + b'\x01\x04' + write, transport=17))
    assert names(operations) == [('writeProperty', 'write')]
    assert ('Role', 'SERVER') in properties(facts, SERVER)

# --- SNMP and banners

def test_snmp_system_description_and_banners():
    sysdescr = 'Siemens, SIMATIC S7, CPU-1200, 6ES7 212-1BD30-0XB0, V.1.0.1'
    _, facts = decode(reply(161, snmp_get_response('1.3.6.1.2.1.1.1.0', sysdescr), transport=17),
                      reply(80, b'HTTP/1.1 200 OK\r\nServer: Allegro-Software-RomPager/4.05\r\nContent-Length: 0\r\n\r\n'),
                      reply(21, b'220 VxWorks FTP server (VxWorks 5.4.2) ready.\r\n'))
    assert {('SystemDescription', sysdescr), ('HTTPServer', 'Allegro-Software-RomPager/4.05'),
            ('FTPBanner', 'VxWorks FTP server (VxWorks 5.4.2) ready.')} <= properties(facts, SERVER)

def test_snmp_set_is_a_write():
    set_request = snmp_get_response('1.3.6.1.2.1.1.5.0', 'renamed', pdu_tag=0xa3)
    operations, facts = decode(request(161, set_request, transport=17))
    assert names(operations) == [('SNMP Set', 'write')]
    assert facts == []  # what a request asks to set isn't what the device is
