# IoT Security Monitoring

Bachelorarbeit – FH Technikum Wien 2026  
**David Fröschl**

Dieses Repository enthält alle Skripte, Konfigurationsdateien und Messdaten zur Bachelorarbeit  
„IoT-Security Monitoring – Evaluation von Security-Monitoring-Ansätzen in ressourcenarmen IoT-Netzwerken".

---

## Projektstruktur

```
iot-monitoring-BA/
├── scripts/                        # Logging- und Steuerungsskripte (Gateway/Monitoring)
│   ├── metrics_logger.py           # Erfassung von CPU, RAM und Netzwerkmetriken
│   ├── mqtt_logger.py              # Protokollierung aller MQTT-Nachrichten
│   ├── mark_event.py               # Zeitmarkierungen für Messphasen
│   ├── logic.py                    # Ereignisbasierte Kamerasteuerung
│   └── analyze_iot_monitoring.py   # Auswertungsskript (PC/Laptop)
├── attacks/                        # Angriffsskripte
│   ├── mqtt_flood.py               # MQTT-Flood DoS-Angriff
│   └── mqtt_injection.py           # MQTT Command Injection
├── config/
│   ├──CameraWebServer_IoT_Device/  # ESP32 CAM ino example Script
│   ├── esphome/                    # ESPHome YAML-Konfigurationen der Sensoren
│   └── docker/
│       └── docker-compose.yml      # Docker-Konfiguration für Suricata und Zeek
├── results/                        # Messdaten (CSV-Dateien)
│   ├── results_gateway_pi/
│   └── results_monitoring_pi/
├── logs/                           # Suricata eve.json und Zeek Log-Dateien
├── plots/                          # Generierte Auswertungsgrafiken
└── evaluation/
    └── evaluation_summary.xlsx     # Aggregierte Auswertungsergebnisse
```

---

## Voraussetzungen

### Gateway (Raspberry Pi 4)
```bash
pip install psutil paho-mqtt requests
```

### Monitoring (Raspberry Pi 5)
- Docker und Docker Compose installiert
- Port-Mirroring am Switch auf das Monitoring-Interface konfiguriert

### Auswertung (PC/Laptop)
```bash
pip install pandas matplotlib openpyxl seaborn
```

---

## Skripte – Verwendung

### metrics_logger.py
Erfasst CPU, RAM und Netzwerkmetriken in definierten Intervallen.

```bash
python3 metrics_logger.py --output gateway_metrics.csv --interval 1 --interface eth0
```

| Parameter | Beschreibung |
|---|---|
| `--output` | Pfad zur Ausgabe-CSV |
| `--interval` | Messintervall in Sekunden (Standard: 1) |
| `--interface` | Netzwerkschnittstelle (optional) |

---

### mqtt_logger.py
Protokolliert alle MQTT-Nachrichten mit Zeitstempel.

```bash
python3 mqtt_logger.py --broker 192.168.X.X --output mqtt_messages.csv
```

| Parameter | Beschreibung |
|---|---|
| `--broker` | IP-Adresse des MQTT-Brokers |
| `--port` | MQTT-Port (Standard: 1883) |
| `--topic` | Topic-Filter (Standard: #) |
| `--output` | Pfad zur Ausgabe-CSV |
| `--username` | Optionaler MQTT-Username |
| `--password` | Optionales MQTT-Passwort |

---

### mark_event.py
Setzt Zeitmarkierungen für die einzelnen Messphasen.

```bash
python3 mark_event.py --file timeline.csv --event RUN_START
python3 mark_event.py --file timeline.csv --event ATTACK_START
python3 mark_event.py --file timeline.csv --event ATTACK_END
python3 mark_event.py --file timeline.csv --event RUN_END
```

| Parameter | Beschreibung |
|---|---|
| `--file` | Pfad zur timeline.csv |
| `--event` | Ereignisname (RUN_START, ATTACK_START, ATTACK_END, RUN_END) |
| `--note` | Optionale Zusatzinfo |

---

### logic.py
Ereignisbasierte Kamerasteuerung — löst bei PIR-Bewegungserkennung einen Snapshot der ESP32-CAM aus.

Vor der Verwendung folgende Placeholder in der Datei anpassen:

```python
MQTT_BROKER = "MQTT_BROKER_IP"   # IP des Raspberry Pi (Gateway)
MQTT_TOPIC  = "MQTT_TOPIC"       # z.B. iot/pir/binary_sensor/motion/state
CAM_IP      = "CAM_IP"           # IP der ESP32-CAM
BASE_DIR    = "BASE_DIR"         # z.B. /home/user/iot
```

```bash
python3 logic.py
```

---

### analyze_iot_monitoring.py
Wertet alle Messdaten aus und erstellt Grafiken und Excel-Auswertung.

```bash
python3 analyze_iot_monitoring.py --results /pfad/zum/results/ordner
```

| Parameter | Beschreibung |
|---|---|
| `--results` | Pfad zum results-Ordner (enthält results_gateway_pi und results_monitoring_pi) |

**Ausgabe:**
- `evaluation_summary.xlsx` — alle Auswertungstabellen
- `plots/` — Grafiken als PNG

---

## Angriffsskripte – Verwendung

### mqtt_flood.py
Simuliert einen DoS-Angriff durch eine hohe Anzahl an MQTT-Nachrichten.

```bash
python3 mqtt_flood.py --broker 192.168.X.X
```

### mqtt_injection.py
Simuliert einen Command Injection-Angriff auf den Shelly Plug.

```bash
python3 mqtt_injection.py --broker 192.168.X.X
```
### NMAP
```bash
while true; do nmap -sS -p 1-1000 192.168.X.X; done
```
---

## Monitoring starten (Docker)

```bash
# Nur Suricata
docker compose up suricata

# Nur Zeek
docker compose up zeek

# Hybrid (beide parallel)
docker compose up suricata zeek
```

Vor dem Start das Interface in der `docker-compose.yml` anpassen:

```yaml
command: -i INTERFACE -l /var/log/suricata   # z.B. eth0
```

---

## Ablauf eines Messlaufs

```
1. Docker Container starten (je nach Szenario)
2. metrics_logger.py starten (Gateway + Monitoring)
3. mqtt_logger.py starten (Gateway)
4. mark_event.py --event RUN_START
5. [Warten – Normalbetrieb]
6. mark_event.py --event ATTACK_START
7. Angriffsskript starten
8. mark_event.py --event ATTACK_END
9. [Warten]
10. mark_event.py --event RUN_END
11. Alle Skripte stoppen
12. Logs und CSVs sichern
```

---

## Systemübersicht

| Komponente | Gerät | Funktion |
|---|---|---|
| Gateway | Raspberry Pi 4 (4 GB) | MQTT-Broker, Logging |
| Monitoring | Raspberry Pi 5 (4 GB) | Suricata, Zeek (Docker) |
| Sensoren | ESP32-S3 Pico | DHT11, MQ, PIR |
| Kamera | ESP32-CAM | HTTP-Stream, Snapshots |
| Aktor | Shelly AZ Plug | Schalten via MQTT/HTTP |
| Angreifer | Laptop (Kali WSL) | Nmap, Angriffsskripte |

---

## Hinweise

- Alle IP-Adressen in den Skripten sind Placeholder und müssen vor der Verwendung angepasst werden
- Suricata erzeugt beim Port-Mirroring von WLAN-Frames „Ethertype unknown" Alerts — diese sind kein echter Fund sondern ein bekannter Effekt und wurden in der Auswertung als Systemrauschen klassifiziert
