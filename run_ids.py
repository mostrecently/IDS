from ids_core import IDSCore, IDSConfig
import time

if __name__ == "__main__":
    config = IDSConfig()
    ids = IDSCore(config)

    print("start IDS...")
    ids.start()

    try:
        # 60 сек
        time.sleep(60)
        # Или while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\nstop IDS...")
    finally:
        ids.stop()
        print("IDS stopped.")


# Example usage:
#   from ids_core import IDSCore, IDSConfig
#   ids = IDSCore(IDSConfig(interface="eth0", rules_path="rules.json"))
#   ids.start()
#   ...
#   ids.stop()
#
# FastAPI example:
#   from fastapi import FastAPI
#   app = FastAPI()
#   ids = IDSCore()
#
#   @app.get("/ids/state")
#   def ids_state():
#       return ids.export_state()