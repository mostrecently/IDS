import time
import signal
import sys
import threading
import uvicorn
from common import FlowTable
from ids_core import PacketSniffer

if __name__ == "__main__":
    ft = FlowTable(timeout=60, cleanup_interval=30)
    ft.start_cleaner()
    sniffer = PacketSniffer(flow_table=ft, interface=None)
    sniffer.start()

    def web_run():
        print(open("logo.txt", "r", encoding="utf-8").read())
        print("ЗАПУСК ВЕБ-СЕРВЕРА")
        print("   http://127.0.0.1:8008")
        uvicorn.run(
            "web_app:app",
            host="0.0.0.0",
            port=8008
        )

    web_thread = threading.Thread(target=web_run, daemon=True)
    web_thread.start()

    def signal_handler(sig, frame):
        print("\nShutting down...")
        sniffer.stop()
        ft.stop_cleaner()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)


    while True:
        time.sleep(1)