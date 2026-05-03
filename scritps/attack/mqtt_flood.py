import paho.mqtt.client as mqtt
import time
import json
import random

broker = "<IP_ADDRESS>"  # Ersetze durch die IP-Adresse deines MQTT-Brokers
topic = "iot/test"

client = mqtt.Client()
client.connect(broker, 1883, 60)

payload = {"value": 0}

print("Start flooding...")

try:
    while True:
        payload["value"] = random.random()
        client.publish(topic, json.dumps(payload))
        time.sleep(0.001)
except KeyboardInterrupt:
    print("Stopped")
