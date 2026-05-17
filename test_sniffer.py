import time
from common import FlowTable
from ids_core import PacketSniffer

ft = FlowTable(timeout=10, cleanup_interval=5)
ft.start_cleaner()
ps = PacketSniffer(flow_table=ft, interface=None)
ps.start()
print("Сниффер запущен, подождите 30 секунд...")
time.sleep(30)
ps.stop()
ft.stop_cleaner()
candidates = ft.get_port_scan_candidates(threshold=10)
print(candidates, len(ft.flows))