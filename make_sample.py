from scapy.all import PcapReader, wrpcap
import time

def make_sample(input_file, output_file, max_packets=10000):
    print(f"Чтение {max_packets} пакетов из {input_file}...")
    start = time.time()
    
    packets = []
    with PcapReader(input_file) as reader:
        for i, pkt in enumerate(reader):
            packets.append(pkt)
            if i % 1000 == 0:
                print(f"  Прочитано {i+1} пакетов...")
            if i >= max_packets - 1:
                break
    
    print(f"Сохранение {len(packets)} пакетов в {output_file}...")
    wrpcap(output_file, packets)
    elapsed = time.time() - start
    print(f"Готово! Затрачено {elapsed:.1f} секунд")

if __name__ == "__main__":
    make_sample(
        input_file="dataset/Tuesday-WorkingHours.pcap",
        output_file="dataset/sample.pcap",
        max_packets=30000
    )