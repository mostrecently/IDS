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

def _save_alert(alert: Alert):
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

class FlowTable:
    def __init__(self, rules_path="rules.json", timeout=60, cleanup_interval=30):
        self._stop_event = threading.Event()
        self._cleaner_thread = None
        self.cleanup_interval = cleanup_interval
        self.timeout = timeout
        self.alerted_ips = set()
        self.rules = self._load_rules(rules_path)
        self.alerted_syn_targets = {}
        self.alerted_udp_targets = {}
        self.alerted_icmp_targets = {}
        self.alerted_bruteforce = {}
        self.alerted_sqli_targets = {}
        self.flows = {}

    def _load_rules(self, path):
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
        
    def _get_rule_config(self, rule_name, defaults):
        rule = self.rules.get(rule_name, {})
        if not rule.get("enabled", True):
            return None
        config = defaults.copy()
        config.update(rule)
        return config

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
            self.check_for_scans()
            self.check_for_syn_flood()
            self.check_for_udp_flood()
            self.check_for_icmp_flood()
            self.check_for_bruteforce()
            self.check_for_sqli()
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

        flows_snapshot = list(self.flows.values())

        for flow in flows_snapshot:
            if flow.src_ip not in src_ports:
                src_ports[flow.src_ip] = set()
            src_ports[flow.src_ip].update(flow.dst_ports)
        candidates = []
        for src_ip, ports in src_ports.items():
            if len(ports) >= threshold:
                    candidates.append((src_ip, len(ports)))
        return candidates
    
    def _save_alert(self, alert: Alert):
        _save_alert(alert)

    def check_for_scans(self, threshold=100):
        defaults = {
            "threshold": 100,
        }
        config = self._get_rule_config("port_scan", defaults)
        if config is None:
            return

        threshold = config["threshold"]

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

    def check_for_syn_flood(self):
        defaults = {
            "threshold": 100,
            "window_seconds": 5,
            "cooldown_seconds": 600
        }
        config = self._get_rule_config("syn_flood", defaults)
        if config is None:
            return

        threshold = config["threshold"]
        window_seconds = config["window_seconds"]
        cooldown_seconds = config["cooldown_seconds"]

        current_time = time.time()
        aggregated = {}

        flows_snapshot = list(self.flows.values())

        for flow in flows_snapshot:
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

    def check_for_udp_flood(self):
        defaults = {
            "threshold": 300,
            "window_seconds": 5,
            "cooldown_seconds": 600
        }
        config = self._get_rule_config("udp_flood", defaults)
        if config is None:
            return

        threshold = config["threshold"]
        window_seconds = config["window_seconds"]
        cooldown_seconds = config["cooldown_seconds"]        
        
        current_time = time.time()
        aggregated = {}

        flows_snapshot = list(self.flows.values())

        for flow in flows_snapshot:
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

    def check_for_icmp_flood(self):
        defaults = {
            "threshold": 50,
            "window_seconds": 5,
            "cooldown_seconds": 600
        }
        config = self._get_rule_config("icmp_flood", defaults)
        if config is None:
            return

        threshold = config["threshold"]
        window_seconds = config["window_seconds"]
        cooldown_seconds = config["cooldown_seconds"]

        current_time = time.time()
        aggregated = {}

        flows_snapshot = list(self.flows.values())

        for flow in flows_snapshot:
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
            if flow.protocol == 1:
                fresh = [ts for ts in flow.icmp_timestamps if ts > (current_time - window_seconds)]
                flow.icmp_timestamps = fresh

    def check_for_bruteforce(self):
        defaults = {
            "threshold": 100,
            "window_seconds": 5,
            "cooldown_seconds": 600,
            "ports": [21, 22, 23, 80, 443, 445, 1433, 3306, 3389]
        }
        config = self._get_rule_config("bruteforce", defaults)
        if config is None:
            return

        threshold = config["threshold"]
        window_seconds = config["window_seconds"]
        cooldown_seconds = config["cooldown_seconds"]
        ports = config["ports"]
        
        current_time = time.time()

        flows_snapshot = list(self.flows.values())

        for flow in flows_snapshot:
            if flow.dst_port not in ports:
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

    def check_for_sqli(self):
        defaults = {
            "enabled": True,
            "ports": [80, 443, 8080],
            "signatures": [
                "' OR '1'='1",
                "' OR 1=1 --",
                "UNION SELECT",
                "DROP TABLE",
                "'; DROP TABLE --",
                "' OR 'x'='x",
                "1 AND 1=1",
                "1 OR 1=1"
            ]
        }
        config = self._get_rule_config("sqli", defaults)
        if config is None:
            return
        
        ports = config.get("ports", [80, 443])
        signatures = [sig.lower() for sig in config.get("signatures", [])]
        current_time = time.time()
        
        for flow in list(self.flows.values()):
            if flow.dst_port not in ports:
                continue
            if flow.protocol != 6:
                continue

            key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            last_alert = self.alerted_sqli_targets.get(key)
            if last_alert is not None and current_time - last_alert < config.get("cooldown_seconds", 600):
                continue
            
            payload = flow.payload.decode('utf-8', errors='ignore').lower()
            for sig in signatures:
                if sig in payload:
                    alert = Alert(
                        timestamp=current_time,
                        src_ip=flow.src_ip,
                        dst_ip=flow.dst_ip,
                        rule_name="SQL Injection",
                        details=f"Detected '{sig}' in payload to {flow.dst_ip}:{flow.dst_port}"
                    )
                    self._save_alert(alert)
                    self.alerted_sqli_targets[key] = current_time
                    break 