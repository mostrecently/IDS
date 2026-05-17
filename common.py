from dataclasses import dataclass, field
from typing import Optional
import time
import threading

@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    first_seen: float
    last_seen: float
    dst_ports: set = field(default_factory=set)
    packets_count: int = 0
    payload: bytes = b''
    syn_count: int = 0

@dataclass
class Alert:
    timestamp: float
    src_ip: str
    dst_ip: str
    rule_name: str
    details: str

@dataclass
class Packet:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    flags: int
    timestamp: float
    payload: bytes

class FlowTable:
    def __init__(self, timeout=60, cleanup_interval=30):
        self._stop_event = threading.Event()
        self._cleaner_thread = None
        self.cleanup_interval = cleanup_interval
        self.timeout = timeout
        self.alerted_ips = set()
        self.flows = {}

    def _make_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> tuple:
        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        return key

    def add_packet(self, pkt):
        key = self._make_key(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        if key in self.flows:
            flow = self.flows[key]
            if(time.time() - flow.last_seen) > self.timeout:
                del self.flows[key]
                flow = Flow(
                    src_ip = pkt.src_ip,
                    dst_ip = pkt.dst_ip,
                    src_port = pkt.src_port,
                    dst_port = pkt.dst_port,
                    protocol = pkt.protocol,
                    first_seen = time.time(),
                    last_seen = time.time(),
                    packets_count = 1
                )
                if hasattr(pkt, 'flags') and (pkt.flags==0x02):
                    flow.syn_count += 1
                    flow.dst_ports.add(pkt.dst_port)
                self.flows[key] = flow
            else:
                if hasattr(pkt, 'flags') and (pkt.flags==0x02):
                    flow.syn_count += 1
                    flow.dst_ports.add(pkt.dst_port)
                flow.last_seen = time.time()
                flow.packets_count += 1
            if hasattr(pkt, "payload"):
                flow.payload += pkt.payload
                flow.payload = flow.payload[-256:]
        else:
            flow = Flow(
                src_ip = pkt.src_ip,
                dst_ip = pkt.dst_ip,
                src_port = pkt.src_port,
                dst_port = pkt.dst_port,
                protocol = pkt.protocol,
                first_seen = time.time(),
                last_seen = time.time(),
                packets_count = 1
            )
            if hasattr(pkt, 'flags') and (pkt.flags==0x02):
                flow.syn_count += 1
                flow.dst_ports.add(pkt.dst_port)
            if hasattr(pkt, "payload"):
                flow.payload += pkt.payload[-256:]
            self.flows[key] = flow
        return flow

    def _cleanup_expired(self):
        for key in list(self.flows.keys()):
            flow = self.flows[key]
            if (time.time() - flow.last_seen) > self.timeout:
                del self.flows[key]

    def _clean_loop(self):
        while not self._stop_event.is_set():
            self._cleanup_expired()
            self._stop_event.wait(self.cleanup_interval)

    def start_cleaner(self):
        cleaner = threading.Thread(target=self._clean_loop, daemon=True)
        self._cleaner_thread = cleaner
        self._cleaner_thread.start()
    
    def stop_cleaner(self):
        self._stop_event.set()
        if self._cleaner_thread is not None:
            self._cleaner_thread.join()

    def get_port_scan_candidates(self, threshold=100):
        src_ports = {}
        for flow in self.flows.values():
            if flow.src_ip not in src_ports:
                src_ports[flow.src_ip] = set()
            src_ports[flow.src_ip].update(flow.dst_ports)
        candidates = []
        for src_ip, ports in src_ports.items():
            if len(ports) >= threshold:
                    candidates.append((src_ip, len(ports)))
        return candidates

    