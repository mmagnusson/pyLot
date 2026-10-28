"""Aggregate decoded packets into hosts, flows, layer-2 observations and fingerprint evidence."""
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass

from parser import protocols
from parser.mac_lookup import lookup_manufacturer

# A MAC that carries traffic for more IPs than this is a router forwarding for them, not their own NIC
GATEWAY_IP_THRESHOLD = 3
BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

@dataclass(slots=True)
class HostStats:
    first_seen: float
    last_seen: float
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

@dataclass(slots=True)
class Traffic:
    first_seen: float
    last_seen: float
    packets: int = 0
    bytes: int = 0

@dataclass(slots=True)
class Evidence:
    confidence: int                  # best (lowest) confidence any packet gave this value
    count: int
    first_frame: int

def is_group_mac(mac):
    """Broadcast and multicast MACs have the low bit of the first octet set."""
    return int(mac[:2], 16) & 1 == 1

class CaptureAnalyzer:
    """
    Accumulates everything pyLot stores about one capture. The *_rows() methods return tuples in the
    column order storage.py expects; with only_dirty=True they return just what changed since the last
    clear_dirty(), which live capture uses to save incrementally.
    """

    def __init__(self, engine):
        self.engine = engine
        self.packet_count = 0
        self.first_seen = self.last_seen = None
        self.hosts = {}                         # ip -> HostStats
        self.flows = {}                         # (src, dst, transport, src_port, dst_port) -> Traffic
        self.macs = {}                          # source MAC -> Traffic
        self.arp = {}                           # (ip, mac) from ARP sender fields -> Traffic
        self.evidence = {}                      # (ip, fingerprint, property, value) -> Evidence
        self.l2_flows = {}                      # (src MAC, dst MAC, protocol) -> Traffic, for frames without IP or ARP
        self.mac_evidence = {}                  # (MAC, protocol, property, value) -> Evidence, from layer-2 announcements
        self.vlans = Counter()                  # (source MAC, VLAN ID) -> frames
        self._src_macs = defaultdict(Counter)   # ip -> MACs its packets came from
        self._dst_macs = defaultdict(Counter)   # ip -> MACs its packets were sent to
        self._mac_ips = defaultdict(set)        # MAC -> IPs it carried, in either direction
        self._dirty = {'flows': set(), 'macs': set(), 'arp': set(), 'evidence': set(), 'l2_flows': set(),
                       'mac_evidence': set(), 'vlans': set()}

    def add(self, pkt):
        self.packet_count += 1
        if self.first_seen is None:
            self.first_seen = pkt.time
        self.last_seen = max(self.last_seen or pkt.time, pkt.time)
        if pkt.src_mac:
            self._count(self.macs, 'macs', pkt.src_mac, pkt)
            if pkt.vlan is not None:
                self.vlans[(pkt.src_mac, pkt.vlan)] += 1
                self._dirty['vlans'].add((pkt.src_mac, pkt.vlan))
        if pkt.l2_protocol:
            self._layer2(pkt)
            return
        if pkt.arp and pkt.arp[2] != '0.0.0.0':  # 0.0.0.0 senders are address-conflict probes
            self._count(self.arp, 'arp', (pkt.arp[2], pkt.arp[1]), pkt)
        if pkt.src_ip is None:
            return

        src, dst = pkt.src_ip, pkt.dst_ip
        host = self._host(src, pkt.time)
        host.packets_sent += 1
        host.bytes_sent += pkt.length
        host = self._host(dst, pkt.time)
        host.packets_received += 1
        host.bytes_received += pkt.length
        if pkt.src_mac:
            self._src_macs[src][pkt.src_mac] += 1
            self._mac_ips[pkt.src_mac].add(src)
        if pkt.dst_mac:
            self._dst_macs[dst][pkt.dst_mac] += 1
            self._mac_ips[pkt.dst_mac].add(dst)
        self._count(self.flows, 'flows', (src, dst, pkt.transport, pkt.src_port or 0, pkt.dst_port or 0), pkt)

        for annotation in self.engine.evaluate(pkt):
            for name, value in annotation.properties.items():
                self._add_evidence(self.evidence, 'evidence', (annotation.ip, annotation.fingerprint, name, value),
                                   annotation.confidence, pkt.frame)

    def _layer2(self, pkt):
        if not pkt.src_mac:
            return
        self._count(self.l2_flows, 'l2_flows', (pkt.src_mac, pkt.dst_mac or '', pkt.l2_protocol), pkt)
        for name, value, confidence in pkt.l2_properties:
            self._add_evidence(self.mac_evidence, 'mac_evidence', (pkt.src_mac, pkt.l2_protocol, name, value), confidence, pkt.frame)

    def _add_evidence(self, table, dirty_name, key, confidence, frame):
        evidence = table.get(key)
        if evidence is None:
            table[key] = Evidence(confidence, 1, frame)
        else:
            evidence.count += 1
            evidence.confidence = min(evidence.confidence, confidence)
        self._dirty[dirty_name].add(key)

    def _host(self, ip, time):
        host = self.hosts.get(ip)
        if host is None:
            host = self.hosts[ip] = HostStats(first_seen=time, last_seen=time)
        else:
            host.last_seen = max(host.last_seen, time)
        return host

    def _count(self, table, dirty_name, key, pkt):
        traffic = table.get(key)
        if traffic is None:
            traffic = table[key] = Traffic(first_seen=pkt.time, last_seen=pkt.time)
        traffic.packets += 1
        traffic.bytes += pkt.length
        traffic.last_seen = max(traffic.last_seen, pkt.time)
        self._dirty[dirty_name].add(key)

    def clear_dirty(self):
        for keys in self._dirty.values():
            keys.clear()

    def _keys(self, table, dirty_name, only_dirty):
        return self._dirty[dirty_name] if only_dirty else table.keys()

    def host_rows(self):
        """(ip, mac, vendor, via_mac, kind, packets/bytes sent/received, first_seen, last_seen) for every host."""
        arp_macs = defaultdict(Counter)  # ip -> MACs ARP bound to it
        arp_ips = defaultdict(set)       # MAC -> IPs ARP bound to it
        for (ip, mac), traffic in self.arp.items():
            arp_macs[ip][mac] += traffic.packets
            arp_ips[mac].add(ip)
        kinds = {ip: self._kind(ip, host) for ip, host in self.hosts.items()}
        rows = []
        for ip, host in self.hosts.items():
            kind = kinds[ip]
            mac = via_mac = None
            if kind == 'unicast':
                if ip in arp_macs:
                    mac = arp_macs[ip].most_common(1)[0][0]
                else:
                    seen = self._src_macs.get(ip) or self._dst_macs.get(ip) or Counter()
                    candidate = next((m for m, _ in seen.most_common() if not is_group_mac(m)), None)
                    # Off-segment hosts arrive with their router's MAC; don't credit it to them. Compare
                    # within one address family, since dual-stack hosts share a MAC across IPv4 and IPv6.
                    ipv6 = ':' in ip
                    carried = sum(1 for other in self._mac_ips[candidate] if kinds.get(other) == 'unicast' and (':' in other) == ipv6) if candidate else 0
                    if candidate and (carried > GATEWAY_IP_THRESHOLD or (not ipv6 and arp_ips.get(candidate, {ip}) != {ip})):
                        via_mac = candidate
                    else:
                        mac = candidate
            rows.append((ip, mac, lookup_manufacturer(mac) if mac else None, via_mac, kind,
                         host.packets_sent, host.packets_received, host.bytes_sent, host.bytes_received,
                         host.first_seen, host.last_seen))
        return rows

    def _kind(self, ip, host):
        address = ipaddress.ip_address(ip)
        if address.is_unspecified:
            return 'unspecified'
        if address.is_multicast:
            return 'multicast'
        dst_macs = self._dst_macs.get(ip)
        if ip == '255.255.255.255' or (host.packets_sent == 0 and dst_macs and set(dst_macs) == {BROADCAST_MAC}):
            return 'broadcast'
        return 'unicast'

    def flow_rows(self, only_dirty=False):
        """(src, dst, transport, src_port, dst_port, protocol, packets, bytes, first_seen, last_seen)"""
        rows = []
        for key in self._keys(self.flows, 'flows', only_dirty):
            src, dst, transport, src_port, dst_port = key
            t = self.flows[key]
            rows.append(key + (protocols.label(transport, src_port, dst_port), t.packets, t.bytes, t.first_seen, t.last_seen))
        return rows

    def mac_rows(self, only_dirty=False):
        """(mac, vendor, packets, bytes, first_seen, last_seen)"""
        return [(mac, lookup_manufacturer(mac), t.packets, t.bytes, t.first_seen, t.last_seen)
                for mac in self._keys(self.macs, 'macs', only_dirty) for t in [self.macs[mac]]]

    def arp_rows(self, only_dirty=False):
        """(ip, mac, packets, first_seen, last_seen)"""
        return [key + (t.packets, t.first_seen, t.last_seen)
                for key in self._keys(self.arp, 'arp', only_dirty) for t in [self.arp[key]]]

    def evidence_rows(self, only_dirty=False):
        """(ip, fingerprint, name, value, confidence, count, first_frame)"""
        return [key + (e.confidence, e.count, e.first_frame)
                for key in self._keys(self.evidence, 'evidence', only_dirty) for e in [self.evidence[key]]]

    def l2_flow_rows(self, only_dirty=False):
        """(src_mac, dst_mac, protocol, packets, bytes, first_seen, last_seen)"""
        return [key + (t.packets, t.bytes, t.first_seen, t.last_seen)
                for key in self._keys(self.l2_flows, 'l2_flows', only_dirty) for t in [self.l2_flows[key]]]

    def mac_evidence_rows(self, only_dirty=False):
        """(mac, protocol, name, value, confidence, count, first_frame)"""
        return [key + (e.confidence, e.count, e.first_frame)
                for key in self._keys(self.mac_evidence, 'mac_evidence', only_dirty) for e in [self.mac_evidence[key]]]

    def vlan_rows(self, only_dirty=False):
        """(mac, vlan, packets)"""
        return [key + (self.vlans[key],) for key in self._keys(self.vlans, 'vlans', only_dirty)]
