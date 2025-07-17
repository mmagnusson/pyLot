import pyshark

def detect_protocol(pkt):
    try:
        # Check for specific protocols in the packet layers
        if hasattr(pkt, 'modbus'):
            return 'Modbus'
        elif hasattr(pkt, 'dnp3'):
            return 'DNP3'
        elif hasattr(pkt, 'bacnet'):
            return 'BACnet'
        elif hasattr(pkt, 'tcp'):
            if pkt.tcp.dstport == '502':
                return 'Modbus'
            elif pkt.tcp.dstport == '20000':
                return 'DNP3'
        elif hasattr(pkt, 'udp'):
            if pkt.udp.dstport == '47808':
                return 'BACnet'
        
        # Return the highest layer if no specific protocol is detected
        return pkt.highest_layer if hasattr(pkt, 'highest_layer') else 'Unknown'
    except Exception as e:
        return 'Unknown'

def parse_pcap(file_path):
    try:
        cap = pyshark.FileCapture(file_path)
        devices = set()
        connections = set()

        for pkt in cap:
            try:
                # Check if packet has IP layer
                if not hasattr(pkt, 'ip'):
                    continue
                    
                ip_src = pkt.ip.src
                ip_dst = pkt.ip.dst
                
                # Skip if source or destination IP is missing
                if not ip_src or not ip_dst:
                    continue
                    
                proto = detect_protocol(pkt)
                devices.add((ip_src, '', ''))
                devices.add((ip_dst, '', ''))
                connections.add((ip_src, ip_dst, proto))
            except AttributeError as e:
                # Skip packets without required attributes
                continue
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue

        cap.close()
        return list(devices), list(connections)
    except Exception as e:
        print(f"Error parsing PCAP file: {e}")
        return [], []
