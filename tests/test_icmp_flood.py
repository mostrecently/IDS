import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from common import FlowTable
from scapy.all import IP, ICMP, send
import time

target_ip = "127.0.0.1"
duration = 30

ft = FlowTable()
ft.start_cleaner()

packet = IP(dst=target_ip) / ICMP()
start = time.time()
count = 0
try:
    while time.time() - start < duration:
        send(packet, verbose=False)
        count += 1
        time.sleep(0.01)
except KeyboardInterrupt:
    print(f"Прервано после {count} пакетов")
else:
    print(f"Отправлено {count} ICMP-пакетов")

time.sleep(10)
ft.stop_cleaner()

print("Проверь alerts.json")