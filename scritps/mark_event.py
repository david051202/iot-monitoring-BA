import argparse
import csv
import os
from datetime import datetime

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--note", default="")
    args = parser.parse_args()

    file_exists = os.path.exists(args.file)

    with open(args.file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "event", "note"])
        writer.writerow([datetime.now().isoformat(timespec="seconds"), args.event, args.note])

    print(f"Ereignis '{args.event}' gespeichert in {args.file}")

if __name__ == "__main__":
    main()
