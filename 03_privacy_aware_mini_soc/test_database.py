
import database
import detector

database.init_db()

events = detector.load_events()
alerts = detector.detect_suspicious_logins(events)

database.save_alerts(alerts)

stored_alerts = database.get_alerts()

print("Events processed:", len(events))
print("Alerts detected:", len(alerts))
print("Alerts stored:", len(stored_alerts))

for alert in stored_alerts:
    print(
        alert["rule"],
        "| Severity:", alert["severity"],
        "| Status:", alert["status"]
    )
