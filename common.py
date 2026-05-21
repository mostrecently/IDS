from dataclasses import dataclass, field, asdict
from typing import Optional
import time
import threading
import json
import os

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
    syn_timestamps: list = field(default_factory=list)
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
        self.alerted_targets = {}
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
                if hasattr(pkt, 'flags') and (pkt.flags==0x02):
                    flow = Flow(
                    src_ip = pkt.src_ip,
                    dst_ip = pkt.dst_ip,
                    src_port = pkt.src_port,
                    dst_port = pkt.dst_port,
                    protocol = pkt.protocol,
                    syn_timestamps = [pkt.timestamp],
                    first_seen = time.time(),
                    last_seen = time.time(),
                    packets_count = 1
                    )
                    flow.syn_count += 1
                    flow.dst_ports.add(pkt.dst_port)
                else:
                    flow = Flow(
                    src_ip = pkt.src_ip,
                    dst_ip = pkt.dst_ip,
                    src_port = pkt.src_port,
                    dst_port = pkt.dst_port,
                    protocol = pkt.protocol,
                    syn_timestamps = [],
                    first_seen = time.time(),
                    last_seen = time.time(),
                    packets_count = 1
                    )
                self.flows[key] = flow
            else:
                if hasattr(pkt, 'flags') and (pkt.flags==0x02):
                    flow.syn_count += 1
                    flow.dst_ports.add(pkt.dst_port)
                    flow.syn_timestamps.append(pkt.timestamp)
                flow.last_seen = time.time()
                flow.packets_count += 1
            if hasattr(pkt, "payload"):
                flow.payload += pkt.payload
                flow.payload = flow.payload[-256:]
        else:
            if hasattr(pkt, 'flags') and (pkt.flags == 0x02):
                flow = Flow(
                src_ip = pkt.src_ip,
                dst_ip = pkt.dst_ip,
                src_port = pkt.src_port,
                dst_port = pkt.dst_port,
                protocol = pkt.protocol,
                syn_timestamps = [pkt.timestamp],
                first_seen = time.time(),
                last_seen = time.time(),
                packets_count = 1
                )
                flow.syn_count += 1
                flow.dst_ports.add(pkt.dst_port)
            else:
                flow = Flow(
                src_ip = pkt.src_ip,
                dst_ip = pkt.dst_ip,
                src_port = pkt.src_port,
                dst_port = pkt.dst_port,
                protocol = pkt.protocol,
                syn_timestamps = [],
                first_seen = time.time(),
                last_seen = time.time(),
                packets_count = 1
                )
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
            self.check_for_scans(threshold=100)
            self.check_for_syn_flood(threshold=100, window_seconds=5)
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

    def _save_alert(self, alert: Alert):
        alert_dict = asdict(alert)
        if os.path.exists("alerts.json"):
            with open("alerts.json", "r", encoding="utf-8") as f:
                alerts = json.load(f)

            alerts.append(alert_dict)

            with open("alerts.json", "w", encoding="utf-8") as f:
                json.dump(alerts, f, indent=2, ensure_ascii=False)
        else:
            alerts = [alert_dict]
            with open("alerts.json", "w", encoding="utf-8") as f:
                json.dump(alerts, f, indent=2, ensure_ascii=False)

    def check_for_scans(self, threshold=100):
        candidates = self.get_port_scan_candidates(threshold)
        for src_ip, ports_count in candidates:
            if src_ip in self.alerted_ips:
                continue
            alert = Alert(
                timestamp=time.time(),
                src_ip=src_ip,
                dst_ip="N/A",
                rule_name="Port scan detected",
                details=f"Scanned {ports_count} unique ports"
            )
            self._save_alert(alert)
            self.alerted_ips.add(src_ip)

    def check_for_syn_flood(self, threshold=100, window_seconds=5, cooldown_seconds=600):
        current_time = time.time()
        for flow in self.flows.values():
            if flow.protocol != 6:
                continue

            last_alert_time = self.alerted_targets.get(flow.dst_ip)
            if last_alert_time is not None:
                if current_time - last_alert_time < cooldown_seconds:
                    continue

            current_syn_timestamps = []
            for t in flow.syn_timestamps:
                if t > (current_time - window_seconds):
                    current_syn_timestamps.append(t)
            flow.syn_timestamps = current_syn_timestamps
            
            if len(current_syn_timestamps) >= threshold:
                alert = Alert(
                timestamp=current_time,
                src_ip="N/A",
                dst_ip=flow.dst_ip,
                rule_name="SYN Flood",
                details=f"{len(current_syn_timestamps)} SYN scanned in last {window_seconds} seconds to {flow.dst_ip}:{flow.dst_port}"
                )
                self._save_alert(alert)
                self.alerted_targets[flow.dst_ip] = current_time