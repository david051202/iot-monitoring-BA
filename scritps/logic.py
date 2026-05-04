import os, time, requests
import paho.mqtt.client as mqtt

# Placeholder
MQTT_BROKER  = "MQTT_BROKER_IP"
MQTT_PORT    = 1883
MQTT_TOPIC   = "MQTT_TOPIC"
CAM_IP       = "CAM_IP"
BASE_DIR     = "BASE_DIR"

LOG_FILE = os.path.join(BASE_DIR, "logs", "log.txt")
IMG_DIR  = os.path.join(BASE_DIR, "images")
CAM_URL  = f"http://{CAM_IP}/capture"
COOLDOWN = 5
last_trigger = 0

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
os.makedirs(IMG_DIR, exist_ok=True)


def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")


def snapshot():
    start = time.time()
    try:
        r = requests.get(CAM_URL, timeout=10)
        duration = time.time() - start
        if r.status_code != 200 or not r.content:
            return False, f"HTTP {r.status_code}", duration
        path = os.path.join(IMG_DIR, f"image_{int(time.time())}.jpg")
        open(path, "wb").write(r.content)
        return True, path, duration
    except Exception as e:
        return False, str(e), time.time() - start


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        client.subscribe(MQTT_TOPIC)
        log("Verbunden mit MQTT-Broker")
    else:
        log(f"Verbindung fehlgeschlagen, Code: {rc}")


def on_message(client, userdata, msg):
    global last_trigger
    payload = msg.payload.decode(errors="ignore").strip()
    log(f"MQTT: {msg.topic} -> {payload}")

    if msg.topic != MQTT_TOPIC or payload != "ON":
        return
    if time.time() - last_trigger < COOLDOWN:
        log("Cooldown aktiv – ignoriert")
        return

    last_trigger = time.time()
    ok, info, dur = snapshot()
    log(f"{'Bild gespeichert' if ok else 'Fehler'}: {info} ({dur:.3f}s)")


if __name__ == "__main__":
    log("Gateway-Logik startet")
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_forever()
