
import json
from datetime import datetime, timedelta
from pathlib import Path

events = []
start = datetime(2026, 10, 26, 9, 0, 0)


def add_event(minutes, username, source_ip, status):
    timestamp = start + timedelta(minutes=minutes)

    events.append({
        "timestamp": timestamp.isoformat(),
        "event_type": "login",
        "username": username,
        "source_ip": source_ip,
        "status": status,
        "host": "linux-lab"
    })


# Normal successful logins
add_event(0, "alice", "192.0.2.10", "success")
add_event(1, "bob", "192.0.2.11", "success")

# Five failed login attempts
for minute in range(2, 7):
    add_event(minute, "admin", "203.0.113.25", "failed")

# Successful login after repeated failures
add_event(7, "admin", "203.0.113.25", "success")

# Additional normal events
add_event(8, "alice", "192.0.2.10", "success")
add_event(9, "bob", "192.0.2.11", "success")
add_event(10, "charlie", "192.0.2.12", "success")
add_event(11, "alice", "192.0.2.10", "success")
add_event(12, "bob", "192.0.2.11", "success")

events.sort(key=lambda event: event["timestamp"])

output = Path("data/events.jsonl")
output.parent.mkdir(parents=True, exist_ok=True)

with output.open("w", encoding="utf-8") as file:
    for event in events:
        file.write(json.dumps(event) + "\n")

print(f"Generated {len(events)} synthetic events.")
print(f"Saved to {output}")
