"""
Read what a switch knows about the physical network from Cisco IOS, IOS-XE and NX-OS command output, as
GRASSMARLIN's physical view did: `show running-config` (hostname, interfaces), `show mac address-table`
(which MAC is behind which port) and `show cdp neighbors detail` or `show lldp neighbors detail` (which
switch is on the other end of a port). Any mix of these can be pasted into one file.
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class Port:
    name: str
    description: Optional[str] = None
    mode: Optional[str] = None       # 'access' or 'trunk'
    vlan: Optional[int] = None       # access VLAN, or native VLAN on a trunk
    shutdown: bool = False

@dataclass
class Neighbor:
    port: str                        # local port
    device: str
    remote_port: Optional[str] = None
    platform: Optional[str] = None
    address: Optional[str] = None

@dataclass
class SwitchData:
    hostname: Optional[str] = None
    ports: Dict[str, Port] = field(default_factory=dict)
    macs: List[tuple] = field(default_factory=list)  # (port, vlan, mac)
    neighbors: List[Neighbor] = field(default_factory=list)

    def is_empty(self):
        return not (self.ports or self.macs or self.neighbors)

# Long and short interface names; the short one is what MAC address tables print and what pyLot stores
INTERFACE_PREFIXES = [
    ('hundredgigabitethernet', 'Hu'), ('hundredgige', 'Hu'), ('fortygigabitethernet', 'Fo'), ('twentyfivegige', 'Twe'),
    ('tengigabitethernet', 'Te'), ('appgigabitethernet', 'Ap'), ('gigabitethernet', 'Gi'), ('fastethernet', 'Fa'),
    ('port-channel', 'Po'), ('ethernet', 'Eth'), ('vlan', 'Vl'), ('loopback', 'Lo'), ('tunnel', 'Tu'),
    ('mgmt', 'mgmt'), ('serial', 'Se'),
    ('twe', 'Twe'), ('hu', 'Hu'), ('fo', 'Fo'), ('te', 'Te'), ('gig', 'Gi'), ('gi', 'Gi'), ('fa', 'Fa'), ('po', 'Po'),
    ('eth', 'Eth'), ('et', 'Eth'), ('vl', 'Vl'), ('lo', 'Lo'), ('tu', 'Tu'), ('se', 'Se'), ('ap', 'Ap'),
]
INTERFACE = re.compile(r'^([A-Za-z][A-Za-z-]*)\s?(\d[\d/.:]*)$')
MAC_PATTERNS = [re.compile(r'^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$'), re.compile(r'^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$')]
PROMPT = re.compile(r'^([A-Za-z0-9_.-]+)(?:\([^)]*\))?[#>]\s*\S')

def interface_name(name):
    """Canonical short name, e.g. GigabitEthernet1/0/1 and Gig 1/0/1 both become Gi1/0/1. None if not an interface."""
    match = INTERFACE.match(name.strip())
    if not match:
        return None
    prefix, number = match.group(1).lower(), match.group(2)
    for long, short in INTERFACE_PREFIXES:
        if prefix == long:
            return short + number
    return match.group(1) + number

def mac_address(token):
    token = token.lower()
    if not any(p.match(token) for p in MAC_PATTERNS):
        return None
    digits = re.sub(r'[^0-9a-f]', '', token)
    return ':'.join(digits[i:i + 2] for i in range(0, 12, 2))

def parse(text):
    data = SwitchData()
    lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    _config(lines, data)
    _mac_table(lines, data)
    _neighbors(lines, data)
    if data.hostname is None:
        prompt = next((m.group(1) for line in lines if (m := PROMPT.match(line))), None)
        data.hostname = prompt
    return data

def _config(lines, data):
    port = None
    for line in lines:
        if line.startswith('hostname ') or line.startswith('switchname '):
            data.hostname = line.split(None, 1)[1].strip().strip('"')
            port = None
        elif line.startswith('interface '):
            name = interface_name(line.split(None, 1)[1])
            port = data.ports.setdefault(name, Port(name)) if name else None
        elif port is not None and line.startswith((' ', '\t')):
            words = line.split()
            if words[:1] == ['description']:
                port.description = line.strip()[len('description'):].strip()
            elif words[:3] == ['switchport', 'mode', 'trunk']:
                port.mode = 'trunk'
            elif words[:3] == ['switchport', 'mode', 'access']:
                port.mode = 'access'
            elif words[:3] == ['switchport', 'access', 'vlan'] and len(words) > 3 and words[3].isdigit():
                port.vlan = int(words[3])
                port.mode = port.mode or 'access'
            elif words[:4] == ['switchport', 'trunk', 'native', 'vlan'] and len(words) > 4 and words[4].isdigit():
                port.vlan = port.vlan if port.mode == 'access' else int(words[4])
            elif words == ['shutdown']:
                port.shutdown = True
        elif not line.startswith((' ', '\t')):
            port = None

def _mac_table(lines, data):
    seen = set()
    for line in lines:
        tokens = line.replace('*', ' ').replace('+', ' ').split()
        mac_index = next((i for i, t in enumerate(tokens) if mac_address(t)), None)
        if mac_index is None or len(tokens) < 3:
            continue
        port = interface_name(tokens[-1])
        if port is None or not re.search(r'dynamic|static|secure', line, re.IGNORECASE):
            continue  # CPU entries, sticky lines without a port, or something that isn't a MAC table
        vlan = next((int(t) for i, t in enumerate(tokens[:-1]) if i != mac_index and t.isdigit()), None)
        entry = (port, vlan, mac_address(tokens[mac_index]))
        if entry not in seen:
            seen.add(entry)
            data.macs.append(entry)

def _neighbors(lines, data):
    """CDP and LLDP detail output: one block per neighbor, separated by dashed lines."""
    blocks, current = [], []
    for line in lines:
        if re.match(r'^-{10,}\s*$', line):
            blocks.append(current)
            current = []
        else:
            current.append(line)
    blocks.append(current)
    for block in blocks:
        text = '\n'.join(block)
        device = _field(text, r'Device ID:\s*(\S+)') or _field(text, r'System Name:\s*(\S+)')
        port = (_field(text, r'Interface:\s*([^,\n]+)') or _field(text, r'Local Intf:\s*(\S+)')
                or _field(text, r'Local Port id:\s*(\S+)'))
        if not device or not port or interface_name(port) is None:
            continue
        remote = _field(text, r'Port ID \(outgoing port\):\s*(\S+)') or _field(text, r'^Port id:\s*(\S+)')
        address = (_field(text, r'IP(?:v4)? [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)')
                   or _field(text, r'Management Addresses:\s*\n\s*IP:\s*(\d+\.\d+\.\d+\.\d+)'))
        platform = _field(text, r'Platform:\s*([^,\n]+)')
        data.neighbors.append(Neighbor(port=interface_name(port), device=_short_hostname(device),
                                       remote_port=interface_name(remote) or remote if remote else None,
                                       platform=platform.strip() if platform else None, address=address))

def _field(text, pattern):
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1).strip() if match else None

def _short_hostname(name):
    """CDP device IDs often carry the domain or a serial number in parentheses."""
    return re.sub(r'\(.*\)$', '', name).split('.')[0]
