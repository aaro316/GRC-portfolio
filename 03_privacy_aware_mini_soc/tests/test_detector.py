
import unittest
from detector import detect_suspicious_logins


class TestLoginDetection(unittest.TestCase):

    def create_event(self, minute, username, ip, status):
        return {
            "timestamp": f"2026-10-26T09:{minute:02d}:00",
            "event_type": "login",
            "username": username,
            "source_ip": ip,
            "status": status,
            "host": "linux-lab"
        }

    def test_normal_successful_login(self):
        events = [
            self.create_event(0, "alice", "192.0.2.10", "success")
        ]

        alerts = detect_suspicious_logins(events)
        self.assertEqual(len(alerts), 0)

    def test_five_failed_attempts(self):
        events = [
            self.create_event(i, "admin", "203.0.113.25", "failed")
            for i in range(5)
        ]

        alerts = detect_suspicious_logins(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "Repeated Failed Logins")

    def test_success_after_three_failures(self):
        events = [
            self.create_event(0, "admin", "203.0.113.25", "failed"),
            self.create_event(1, "admin", "203.0.113.25", "failed"),
            self.create_event(2, "admin", "203.0.113.25", "failed"),
            self.create_event(3, "admin", "203.0.113.25", "success")
        ]

        alerts = detect_suspicious_logins(events)

        self.assertTrue(any(
            alert["rule"] == "Successful Login After Repeated Failures"
            for alert in alerts
        ))

    def test_failures_outside_five_minute_window(self):
        events = [
            self.create_event(0, "admin", "203.0.113.25", "failed"),
            self.create_event(2, "admin", "203.0.113.25", "failed"),
            self.create_event(4, "admin", "203.0.113.25", "failed"),
            self.create_event(6, "admin", "203.0.113.25", "failed"),
            self.create_event(8, "admin", "203.0.113.25", "failed")
        ]

        alerts = detect_suspicious_logins(events)

        self.assertFalse(any(
            alert["rule"] == "Repeated Failed Logins"
            for alert in alerts
        ))

    def test_failures_from_different_ips(self):
        events = [
            self.create_event(0, "admin", "203.0.113.25", "failed"),
            self.create_event(1, "admin", "203.0.113.26", "failed"),
            self.create_event(2, "admin", "203.0.113.27", "failed"),
            self.create_event(3, "admin", "203.0.113.28", "failed"),
            self.create_event(4, "admin", "203.0.113.29", "failed")
        ]

        alerts = detect_suspicious_logins(events)

        self.assertFalse(any(
            alert["rule"] == "Repeated Failed Logins"
            for alert in alerts
        ))


if __name__ == "__main__":
    unittest.main()

