import argparse
import csv
from datetime import datetime
import paho.mqtt.client as mqtt

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker", required=True)
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--topic", default="#")
    parser.add_argument("--output", required=True)
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    args = parser.parse_args()

    f = open(args.output, "w", newline="", encoding="utf-8")
    writer = csv.writer(f)
    writer.writerow(["timestamp", "topic", "payload_size_bytes", "payload_preview"])

    def on_connect(client, userdata, flags, rc, properties=None):
        if rc == 0:
            print(f"Verbunden mit {args.broker}:{args.port}, abonniere '{args.topic}'")
            client.subscribe(args.topic)
        else:
            print(f"MQTT-Verbindung fehlgeschlagen, Code: {rc}")

    def on_message(client, userdata, msg):
        payload = msg.payload.decode("utf-8", errors="replace")
        writer.writerow([
            datetime.now().isoformat(timespec="seconds"),
            msg.topic,
            len(msg.payload),
            payload[:120]
        ])
        f.flush()

    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    except Exception:
        client = mqtt.Client()

    if args.username:
        client.username_pw_set(args.username, args.password)

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(args.broker, args.port, 60)
        client.loop_forever()
    except KeyboardInterrupt:
        print(f"\nGestoppt. CSV gespeichert unter: {args.output}")
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
        f.close()

if __name__ == "__main__":
    main()
