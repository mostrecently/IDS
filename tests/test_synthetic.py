import sys
import os
import time
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from common import FlowTable, Packet

ft = FlowTable(timeout=60, cleanup_interval=30)

ft.start_cleaner()


for port in range(1, 26):
    packet = Packet(
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=12345 + port,  
        dst_port=port,
        protocol=6,   
        flags=2,      
        timestamp=time.time(),
        payload=b""
    )
    ft.add_packet(packet)
    print(f"Добавлен пакет на порт {port}")

time.sleep(2)

ft.check_for_scans(threshold=20)

candidates = ft.get_port_scan_candidates(threshold=20)
print(f"Кандидаты: {candidates}")

ft.stop_cleaner()