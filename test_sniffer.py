import time
from common import FlowTable
from ids_core import PacketSniffer

ft = FlowTable(timeout=10, cleanup_interval=5)
ft.start_cleaner()
sniffer = PacketSniffer(flow_table=ft, interface=None)
sniffer.start()
print("Сниффер запущен, подождите 30 секунд...")
time.sleep(30)
sniffer.stop()
ft.stop_cleaner()
candidates = ft.get_port_scan_candidates(threshold=10)
print(candidates, len(ft.flows))