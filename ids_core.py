from __future__ import annotations
import json
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple
from scapy.all import AsyncSniffer, IP, IPv6, Raw, TCP, UDP, ICMP  # type: ignore


FlowKey = Tuple[str, str, Optional[int], Optional[int], str]


def _now() -> float:
    return time.time()

# преобразуем payload в строку json, utf-8, latin-1 или hex
def _safe_payload(raw_bytes: bytes, max_len: int = 512) -> str:
    if not raw_bytes:
        return ""

    clipped = raw_bytes[:max_len]

    try:
        text = clipped.decode("utf-8")
        # Make sure it stays reasonably printable.
        printable = sum(ch.isprintable() or ch.isspace() for ch in text)
        if printable / max(1, len(text)) >= 0.8:
            return text
    except Exception:
        pass

    try:
        return clipped.decode("latin-1")
    except Exception:
        return clipped.hex()


@dataclass
class IDSConfig:
    interface: Optional[str] = None
    rules_path: str = "rules.json"
    bpf_filter: str = "ip or ip6"
    max_payload_len: int = 256
    recent_events_limit: int = 1000
    recent_alerts_limit: int = 500


class IDSCore:
    """
    Core IDS engine.

    Public methods are designed for easy FastAPI integration:
    - start()
    - stop()
    - get_flows()
    - get_alerts()
    - export_state()
    """

    def __init__(self, config: Optional[IDSConfig] = None) -> None:
        self.config = config or IDSConfig()

        self._lock = threading.RLock()
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False

        self.flows: Dict[FlowKey, Dict[str, Any]] = {} #словарь
        self.recent_events: Deque[Dict[str, Any]] = deque(maxlen=self.config.recent_events_limit)
        self.alerts: Deque[Dict[str, Any]] = deque(maxlen=self.config.recent_alerts_limit)
        self.rules: List[Dict[str, Any]] = []

        self.load_rules(self.config.rules_path)

    # ----------------------------
    # Rules
    # ----------------------------
    
    def load_rules(self, rules_path: str) -> None:
    #загружаем правила из json

        path = Path(rules_path)
        if not path.exists():
            self.rules = []
            return

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            rules = data.get("rules", [])
            self.rules = rules if isinstance(rules, list) else []
        except Exception:
            # Fail closed on malformed rules file: no rules loaded.
            self.rules = []

    # Lifecycle
    def start(self) -> None:
        if self._running:
            return

        self._sniffer = AsyncSniffer(
            iface=self.config.interface,
            filter=self.config.bpf_filter,
            store=False,
            prn=self._handle_packet,
        )
        self._sniffer.start()
        self._running = True

    def stop(self) -> None:
        if not self._running:
            return

        try:
            if self._sniffer is not None:
                self._sniffer.stop()
        finally:
            self._sniffer = None
            self._running = False

    @property
    def running(self) -> bool:
        return self._running

    # Packet processing
    def _handle_packet(self, pkt) -> None:
        #Scapy callback. Prints pkt.summary() and updates flow table + detections.

        try:
            print(pkt.summary())
        except Exception:
            pass

        info = self._extract_packet_info(pkt)
        if info is None:
            return

        now = _now()
        flow_key: FlowKey = (
            info["src_ip"],
            info["dst_ip"],
            info["src_port"],
            info["dst_port"],
            info["protocol"],
        )

        with self._lock:
            flow = self.flows.get(flow_key)
            if flow is None:
                flow = {
                    "src_ip": info["src_ip"],
                    "dst_ip": info["dst_ip"],
                    "src_port": info["src_port"],
                    "dst_port": info["dst_port"],
                    "protocol": info["protocol"],
                    "first_seen": now,
                    "last_seen": now,
                    "payload": info["payload"],
                    "packets_count": 1,
                }
                self.flows[flow_key] = flow
            else:
                flow["last_seen"] = now
                flow["packets_count"] += 1
                if info["payload"]:
                    flow["payload"] = info["payload"]

            event = {
                "timestamp": now,
                **info,
                "flow_key": {
                    "src_ip": info["src_ip"],
                    "dst_ip": info["dst_ip"],
                    "src_port": info["src_port"],
                    "dst_port": info["dst_port"],
                    "protocol": info["protocol"],
                },
            }
            self.recent_events.append(event)

            alerts = self._detect(info)
            for alert in alerts:
                self.alerts.append(alert)

    def _extract_packet_info(self, pkt) -> Optional[Dict[str, Any]]:
        # IP / IPv6 source and destination
        src_ip = None
        dst_ip = None

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto_num = int(pkt[IP].proto)
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            proto_num = int(pkt[IPv6].nh)
        else:
            return None

        protocol = self._protocol_name(pkt, proto_num)

        src_port = None
        dst_port = None
        if TCP in pkt:
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
        elif UDP in pkt:
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        elif ICMP in pkt:
            src_port = None
            dst_port = None

        payload_bytes = b""
        if Raw in pkt:
            try:
                payload_bytes = bytes(pkt[Raw].load)
            except Exception:
                payload_bytes = b""

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "payload": _safe_payload(payload_bytes, self.config.max_payload_len),
        }

    def _protocol_name(self, pkt, proto_num: int) -> str:
        if TCP in pkt:
            return "TCP"
        if UDP in pkt:
            return "UDP"
        if ICMP in pkt:
            return "ICMP"
        if proto_num == 6:
            return "TCP"
        if proto_num == 17:
            return "UDP"
        if proto_num == 1:
            return "ICMP"
        return f"IP_PROTO_{proto_num}"

    # ----------------------------
    # Detection
    # ----------------------------
    def _detect(self, info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Very small rule engine.

        Supported rule keys:
        - enabled: bool
        - protocol: str
        - src_ip / dst_ip: str
        - src_port / dst_port: int or list[int]
        - payload_contains: str
        - payload_regex: str  (optional; simple substring matching is used here)
        - min_payload_len: int
        - action: str
        - severity: str
        - description: str
        """
        alerts: List[Dict[str, Any]] = []

        payload = info.get("payload") or ""
        payload_lower = payload.lower()

        for rule in self.rules:
            if not isinstance(rule, dict):
                continue
            if not rule.get("enabled", True):
                continue

            if "protocol" in rule and str(rule["protocol"]).upper() != str(info["protocol"]).upper():
                continue

            if "src_ip" in rule and str(rule["src_ip"]) != str(info["src_ip"]):
                continue

            if "dst_ip" in rule and str(rule["dst_ip"]) != str(info["dst_ip"]):
                continue

            if "src_port" in rule and not self._port_match(info.get("src_port"), rule["src_port"]):
                continue

            if "dst_port" in rule and not self._port_match(info.get("dst_port"), rule["dst_port"]):
                continue

            if "min_payload_len" in rule:
                try:
                    if len(payload) < int(rule["min_payload_len"]):
                        continue
                except Exception:
                    continue

            if "payload_contains" in rule:
                needle = str(rule["payload_contains"]).lower()
                if needle not in payload_lower:
                    continue

            # Optional compatibility key; treated as substring.
            if "payload_regex" in rule:
                needle = str(rule["payload_regex"]).lower()
                if needle and needle not in payload_lower:
                    continue

            alerts.append(
                {
                    "timestamp": _now(),
                    "rule_id": rule.get("id"),
                    "name": rule.get("name", "unnamed-rule"),
                    "severity": rule.get("severity", "medium"),
                    "action": rule.get("action", "alert"),
                    "description": rule.get("description", ""),
                    "packet": {
                        "src_ip": info["src_ip"],
                        "dst_ip": info["dst_ip"],
                        "src_port": info["src_port"],
                        "dst_port": info["dst_port"],
                        "protocol": info["protocol"],
                        "payload": info["payload"],
                    },
                }
            )

        return alerts

    def _port_match(self, actual: Optional[int], expected: Any) -> bool:
        if expected is None:
            return True
        if actual is None:
            return False

        if isinstance(expected, (list, tuple, set)):
            try:
                return int(actual) in {int(x) for x in expected}
            except Exception:
                return False

        try:
            return int(actual) == int(expected)
        except Exception:
            return False

    # под FastAPI-френдли методы
    def get_flows(self) -> List[Dict[str, Any]]:
        with self._lock:
            return sorted(self.flows.values(), key=lambda x: x["last_seen"], reverse=True)

    def get_alerts(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.alerts)

    def get_recent_events(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.recent_events)

    def export_state(self) -> Dict[str, Any]:
        """
        JSON-ready snapshot for FastAPI.
        """
        return {
            "running": self.running,
            "flows": self.get_flows(),
            "alerts": self.get_alerts(),
            "events": self.get_recent_events(),
            "flows_count": len(self.flows),
            "alerts_count": len(self.alerts),
        }

