import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path


def load_events(file_path="data/events.jsonl"):
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                events.append(json.loads(line))

    events.sort(key=lambda event: datetime.fromisoformat(event["timestamp"]))
    return events


def detect_suspicious_logins(events):
    alerts = []
    failed_by_ip = defaultdict(deque)
    failed_by_account = defaultdict(deque)
    detected_brute_force_ips = set()

    for event in events:
        timestamp = datetime.fromisoformat(event["timestamp"])
        username = event["username"]
        source_ip = event["source_ip"]
        status = event["status"]

        if status == "failed":
            # Rule 1: Count failures from the same IP in five minutes.
            ip_attempts = failed_by_ip[source_ip]

            while ip_attempts and timestamp - ip_attempts[0] > timedelta(minutes=5):
                ip_attempts.popleft()

            ip_attempts.append(timestamp)

            if len(ip_attempts) >= 5 and source_ip not in detected_brute_force_ips:
                alerts.append({
                    "rule": "Repeated Failed Logins",
                    "severity": "High",
                    "timestamp": event["timestamp"],
                    "source_ip": source_ip,
                    "username": username,
                    "description": "At least five failed logins from one IP within five minutes."
                })
                detected_brute_force_ips.add(source_ip)

            # Track failures for this particular account and IP.
            account_key = (username, source_ip)
            account_attempts = failed_by_account[account_key]

            while account_attempts and timestamp - account_attempts[0] > timedelta(minutes=10):
                account_attempts.popleft()

            account_attempts.append(timestamp)

        elif status == "success":
            # Rule 2: Check for recent failures before a successful login.
            account_key = (username, source_ip)
            account_attempts = failed_by_account[account_key]

            while account_attempts and timestamp - account_attempts[0] > timedelta(minutes=10):
                account_attempts.popleft()

            if len(account_attempts) >= 3:
                alerts.append({
                    "rule": "Successful Login After Repeated Failures",
                    "severity": "High",
                    "timestamp": event["timestamp"],
                    "source_ip": source_ip,
                    "username": username,
                    "description": "Successful login after at least three recent failures for the same account and IP."
                })

                # Prevent the same failures from repeatedly triggering alerts.
                account_attempts.clear()

    return alerts


if __name__ == "__main__":
    events_path = Path("data/events.jsonl")

    if not events_path.exists():
        print("Sample data not found. Generate it first.")
    else:
        events = load_events(events_path)
        alerts = detect_suspicious_logins(events)

        print(f"Events processed: {len(events)}")
        print(f"Alerts generated: {len(alerts)}")

        for alert in alerts:
            print(json.dumps(alert, indent=2))
