import sys
import os
import time
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from common import FlowTable, Packet

ft = FlowTable()
ft.start_cleaner()

for i in range(20):
    packet = Packet(
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        src_port=12345 + i,
        dst_port=80,
        protocol=6,
        flags=0x02,
        timestamp=time.time(),
        payload=b"GET /?id=1'+OR+'1'='1 HTTP/1.1"
    )
    ft.add_packet(packet)
    time.sleep(0.5)  

time.sleep(35)
ft.stop_cleaner()
print("Проверь alerts.json")