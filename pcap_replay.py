import time
from scapy.all import PcapReader
from common import FlowTable
from ids_core import PacketSniffer

def replay_pcap(pcap_path, max_packets=None):
    """
    Воспроизводит PCAP-файл через IDS
    max_packets — ограничение на количество пакетов (для теста)
    """
    print(f"Загрузка IDS...")
    ft = FlowTable()
    ft.start_cleaner()
    sniffer = PacketSniffer(flow_table=ft)
    
    print(f"Чтение {pcap_path}...")
    packet_count = 0
    
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if max_packets and packet_count >= max_packets:
                break
            
            sniffer._packet_handler(pkt)
            packet_count += 1
            
            if packet_count % 1000 == 0:
                print(f"Обработано {packet_count} пакетов...")
    
    print(f"Всего обработано {packet_count} пакетов")
    print("Ожидание срабатывания детектов (30 секунд)...")
    time.sleep(30)
    
    ft.stop_cleaner()
    print("Проверь alerts.json")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    else:
        pcap_file = "dataset/sample.pcap"

    max_packets = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    replay_pcap(pcap_file, max_packets)