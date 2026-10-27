"""Label flows by well-known port. Fingerprints add the authoritative ICSProtocol detail on hosts."""

IP_PROTOCOLS = {1: 'ICMP', 2: 'IGMP', 4: 'IP-in-IP', 6: 'TCP', 17: 'UDP', 41: 'IPv6-in-IPv4', 47: 'GRE',
                50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 103: 'PIM', 112: 'VRRP', 132: 'SCTP'}

ICS_PORTS = {
    (6, 102): 'S7comm', (6, 502): 'Modbus', (17, 502): 'Modbus', (6, 789): 'Red Lion Crimson',
    (6, 1911): 'Niagara Fox', (6, 4911): 'Niagara Fox', (6, 1962): 'PCWorx', (6, 2222): 'EtherNet/IP I/O',
    (17, 2222): 'EtherNet/IP I/O', (6, 2404): 'IEC 60870-5-104', (6, 2455): 'CODESYS', (6, 4840): 'OPC UA',
    (6, 5007): 'MELSEC', (17, 5007): 'MELSEC', (6, 9600): 'OMRON FINS', (17, 9600): 'OMRON FINS',
    (6, 18245): 'GE SRTP', (6, 20000): 'DNP3', (17, 20000): 'DNP3', (6, 20547): 'ProConOS',
    (6, 44818): 'EtherNet/IP', (17, 44818): 'EtherNet/IP', (17, 47808): 'BACnet', (6, 34962): 'PROFINET',
    (17, 34964): 'PROFINET', (17, 18246): 'GE EGD', (6, 1089): 'Foundation Fieldbus HSE',
}

IT_PORTS = {
    (6, 20): 'FTP-Data', (6, 21): 'FTP', (6, 22): 'SSH', (6, 23): 'Telnet', (6, 25): 'SMTP', (17, 53): 'DNS',
    (6, 53): 'DNS', (17, 67): 'DHCP', (17, 68): 'DHCP', (17, 69): 'TFTP', (6, 80): 'HTTP', (17, 123): 'NTP',
    (6, 135): 'MS-RPC', (17, 137): 'NetBIOS-NS', (17, 138): 'NetBIOS-DGM', (6, 139): 'NetBIOS-SSN',
    (6, 143): 'IMAP', (17, 161): 'SNMP', (17, 162): 'SNMP Trap', (6, 389): 'LDAP', (17, 389): 'LDAP',
    (6, 443): 'HTTPS', (17, 443): 'QUIC', (6, 445): 'SMB', (17, 514): 'Syslog', (6, 636): 'LDAPS',
    (17, 1812): 'RADIUS', (17, 1900): 'SSDP', (17, 1947): 'Sentinel HASP', (6, 3389): 'RDP',
    (17, 3702): 'WS-Discovery', (17, 5353): 'mDNS', (17, 5355): 'LLMNR', (6, 5900): 'VNC',
    (6, 5985): 'WinRM', (6, 5986): 'WinRM', (6, 8080): 'HTTP-Alt', (6, 8443): 'HTTPS-Alt',
}

PORT_LABELS = {**IT_PORTS, **ICS_PORTS}

def label(transport, src_port, dst_port):
    """Best-guess application protocol for a flow, preferring the destination (service) port."""
    for port in (dst_port, src_port):
        name = PORT_LABELS.get((transport, port))
        if name:
            return name
    return IP_PROTOCOLS.get(transport, f'IP proto {transport}') if transport is not None else 'Unknown'
