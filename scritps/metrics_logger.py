import argparse
import csv
import os
import socket
import time
from datetime import datetime
import psutil

def get_net_counters(interface):
    if interface:
        counters = psutil.net_io_counters(pernic=True)
        if interface not in counters:
            raise ValueError(f"Interface '{interface}' nicht gefunden. Verfügbar: {', '.join(counters.keys())}")
        return counters[interface]
    return psutil.net_io_counters()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--interface", default=None)
    args = parser.parse_args()

    hostname = socket.gethostname()
    psutil.cpu_percent(interval=None)
    prev_net = get_net_counters(args.interface)

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "hostname", "cpu_percent",
            "ram_percent", "ram_used_mb", "ram_available_mb",
            "load_1", "load_5", "load_15",
            "bytes_sent_total", "bytes_recv_total",
            "bytes_sent_diff", "bytes_recv_diff",
            "packets_sent_total", "packets_recv_total",
            "packets_sent_diff", "packets_recv_diff",
        ])

        try:
            while True:
                mem = psutil.virtual_memory()
                net = get_net_counters(args.interface)

                try:
                    load_1, load_5, load_15 = os.getloadavg()
                except OSError:
                    load_1 = load_5 = load_15 = 0.0

                writer.writerow([
                    datetime.now().isoformat(timespec="seconds"),
                    hostname,
                    psutil.cpu_percent(interval=None),
                    mem.percent,
                    round(mem.used / 1024**2, 2),
                    round(mem.available / 1024**2, 2),
                    round(load_1, 4), round(load_5, 4), round(load_15, 4),
                    net.bytes_sent, net.bytes_recv,
                    net.bytes_sent - prev_net.bytes_sent,
                    net.bytes_recv - prev_net.bytes_recv,
                    net.packets_sent, net.packets_recv,
                    net.packets_sent - prev_net.packets_sent,
                    net.packets_recv - prev_net.packets_recv,
                ])
                f.flush()
                prev_net = net
                time.sleep(args.interval)

        except KeyboardInterrupt:
            print(f"\nGestoppt. CSV gespeichert unter: {args.output}")

if __name__ == "__main__":
    main()
