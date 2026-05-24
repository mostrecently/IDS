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
    udp_timestamps: list = field(default_factory=list)
    icmp_timestamps: list = field(default_factory=list)
    packet_timestamps: list = field(default_factory=list)
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
        self.alerted_syn_targets = {}
        self.alerted_udp_targets = {}
        self.alerted_icmp_targets = {}
        self.alerted_bruteforce = {}
        self.flows = {}

    def _make_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> tuple:
        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        return key

    def add_packet(self, pkt):
        key = self._make_key(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        if key in self.flows:
            flow = self.flows[key]
            if (time.time() - flow.last_seen) > self.timeout:
                del self.flows[key]
                flow = None
        else:
            flow = None
    
        if flow is None:
            flow = Flow(
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol,
                first_seen=time.time(),
                last_seen=time.time(),
                packets_count=1
            )
            if pkt.protocol == 6:
                if hasattr(pkt, 'flags') and (pkt.flags == 0x02):
                    flow.syn_timestamps = [pkt.timestamp]
                    flow.syn_count = 1
                    flow.dst_ports.add(pkt.dst_port)
            elif pkt.protocol == 17:
                flow.udp_timestamps = [pkt.timestamp]
                flow.dst_ports.add(pkt.dst_port)
            elif pkt.protocol == 1:
                flow.icmp_timestamps = [pkt.timestamp]
            

            self.flows[key] = flow
            if hasattr(pkt, "payload"):
                flow.payload = pkt.payload[-256:]
            flow.packet_timestamps.append(pkt.timestamp)
            return flow
    
        flow.last_seen = time.time()
        flow.packets_count += 1
        if hasattr(pkt, "payload"):
            flow.payload += pkt.payload
            flow.payload = flow.payload[-256:]

        if pkt.protocol == 6:
            if hasattr(pkt, 'flags') and (pkt.flags == 0x02):
                flow.syn_count += 1
                flow.syn_timestamps.append(pkt.timestamp)
                flow.dst_ports.add(pkt.dst_port)
        elif pkt.protocol == 17:
            flow.udp_timestamps.append(pkt.timestamp)
            flow.dst_ports.add(pkt.dst_port)
        elif pkt.protocol == 1:
            flow.icmp_timestamps.append(pkt.timestamp)
        flow.packet_timestamps.append(pkt.timestamp)
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
            self.check_for_udp_flood(threshold=100, window_seconds=5)
            self.check_for_icmp_flood(threshold=100, window_seconds=5)
            self.check_for_bruteforce(threshold=10, window_seconds=5)
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

    def check_for_syn_flood(self, threshold=100, window_seconds=5, cooldown_seconds=5):
        current_time = time.time()

        aggregated = {}
        for flow in self.flows.values():
            if flow.protocol != 6:
                continue
            if flow.dst_ip not in aggregated:
                aggregated[flow.dst_ip] = []
            for ts in flow.syn_timestamps:
                if ts > (current_time - window_seconds):
                    aggregated[flow.dst_ip].append(ts)
        
        for dst_ip, timestamps in aggregated.items():
            last_alert = self.alerted_syn_targets.get(dst_ip)
            if last_alert is not None and current_time - last_alert < cooldown_seconds:
                continue
            
            if len(timestamps) >= threshold:
                alert = Alert(
                    timestamp=current_time,
                    src_ip="N/A",
                    dst_ip=dst_ip,
                    rule_name="SYN Flood",
                    details=f"{len(timestamps)} SYN packets in last {window_seconds} seconds to {dst_ip}"
                )
                self._save_alert(alert)
                self.alerted_syn_targets[dst_ip] = current_time
        
        for flow in self.flows.values():
            if flow.protocol == 6:
                fresh = [ts for ts in flow.syn_timestamps if ts > (current_time - window_seconds)]
                flow.syn_timestamps = fresh

    def check_for_udp_flood(self, threshold=500, window_seconds=5, cooldown_seconds=5):
        current_time = time.time()
        
        aggregated = {}
        for flow in self.flows.values():
            if flow.protocol != 17:
                continue
            if flow.dst_ip not in aggregated:
                aggregated[flow.dst_ip] = []
            for ts in flow.udp_timestamps:
                if ts > (current_time - window_seconds):
                    aggregated[flow.dst_ip].append(ts)

        for dst_ip, timestamps in aggregated.items():
            last_alert = self.alerted_udp_targets.get(dst_ip)
            if last_alert is not None and current_time - last_alert < cooldown_seconds:
                continue
            
            if len(timestamps) >= threshold:
                alert = Alert(
                    timestamp=current_time,
                    src_ip="N/A",
                    dst_ip=dst_ip,
                    rule_name="UDP Flood",
                    details=f"{len(timestamps)} UDP packets in last {window_seconds} seconds to {dst_ip}"
                )
                self._save_alert(alert)
                self.alerted_udp_targets[dst_ip] = current_time
        
        for flow in self.flows.values():
            if flow.protocol == 17:
                fresh = [ts for ts in flow.udp_timestamps if ts > (current_time - window_seconds)]
                flow.udp_timestamps = fresh

    def check_for_icmp_flood(self, threshold=50, window_seconds=5, cooldown_seconds=5):
        current_time = time.time()
        
        aggregated = {}
        for flow in self.flows.values():
            if flow.protocol != 1:
                continue
            if flow.dst_ip not in aggregated:
                aggregated[flow.dst_ip] = []
            for ts in flow.icmp_timestamps:
                if ts > (current_time - window_seconds):
                    aggregated[flow.dst_ip].append(ts)

        for dst_ip, timestamps in aggregated.items():
            last_alert = self.alerted_icmp_targets.get(dst_ip)
            if last_alert is not None and current_time - last_alert < cooldown_seconds:
                continue
            
            if len(timestamps) >= threshold:
                alert = Alert(
                    timestamp=current_time,
                    src_ip="N/A",
                    dst_ip=dst_ip,
                    rule_name="ICMP Flood",
                    details=f"{len(timestamps)} ICMP packets in last {window_seconds} seconds to {dst_ip}"
                )
                self._save_alert(alert)
                self.alerted_icmp_targets[dst_ip] = current_time
        
        for flow in self.flows.values():
            if flow.protocol == 17:
                fresh = [ts for ts in flow.icmp_timestamps if ts > (current_time - window_seconds)]
                flow.icmp_timestamps = fresh

    def check_for_bruteforce(self, threshold=10, window_seconds=5, cooldown_seconds=5):
        bruteforce_ports = {21, 22, 23, 80, 443, 445, 1433, 3306, 3389}
        current_time = time.time()

        for flow in self.flows.values():
            if flow.dst_port not in bruteforce_ports:
                continue
            if flow.protocol != 6:
                continue

            key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            last_alert = self.alerted_bruteforce.get(key)
            if last_alert is not None and current_time - last_alert < cooldown_seconds:
                continue
            
            fresh = [ts for ts in flow.packet_timestamps if ts > current_time - window_seconds]
            flow.packet_timestamps = fresh

            if len(fresh) >= threshold:
                alert = Alert (
                    timestamp=current_time,
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    rule_name="Bruteforce",
                    details=f"{len(fresh)} packets in last {window_seconds} seconds to {flow.dst_ip}:{flow.dst_port}"
                )
                self._save_alert(alert)
                self.alerted_bruteforce[key] = current_time