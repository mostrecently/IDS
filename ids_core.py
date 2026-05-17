from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw
import time
import threading
from common import FlowTable, Packet

class PacketSniffer:
    def __init__(self, flow_table: FlowTable, interface: str = None):
        self.flow_table = flow_table
        self.interface = interface 
        self.running = False
        self.sniffer_thread = None

    def _extract_packet_info(self, pkt):
        src_ip = None
        dst_ip = None
        protocol = None
        src_port = None
        dst_port = None
        flags = None
        payload = None
        
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = pkt[IP].proto
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            protocol = pkt[IPv6].nh
        else:
            return None

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = pkt[TCP].flags
        
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            flags = 0

        else:
            src_port = 0
            dst_port = 0
            flags = 0

        if Raw in pkt:
            raw_bytes = bytes(pkt[Raw].load)
            payload = raw_bytes[:256]
        else:
            payload = b''
        
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "flags": flags,
            "payload": payload
        }
    
    def _packet_handler(self, pkt):
        info = self._extract_packet_info(pkt)

        if info is None:
            return

        packet = Packet(
            src_ip=info["src_ip"],
            dst_ip=info["dst_ip"],
            src_port=info["src_port"],
            dst_port=info["dst_port"],
            protocol=info["protocol"],
            flags=info["flags"],
            timestamp=time.time(),
            payload=info["payload"]
        )

        self.flow_table.add_packet(packet)
    
    def _sniff_loop(self):
        stop_filter = lambda x: not self.running
        sniff(iface=self.interface, prn=self._packet_handler, stop_filter=stop_filter, store=False)
    
    def start(self):
        self.running = True
        self.sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniffer_thread.start()

    def stop(self):
        self.running = False
        if self.sniffer_thread is not None:
            self.sniffer_thread.join()