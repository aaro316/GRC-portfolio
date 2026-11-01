
import hashlib
import sqlite3
from pathlib import Path

DB_PATH = Path("data/soc.db")


def init_db():
    """Create the alerts table if it does not exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                username TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open'
            )
        """)

def save_alerts(alerts):
    """Save alerts without inserting duplicates."""
    with sqlite3.connect(DB_PATH) as connection:
        for alert in alerts:
            identity = "|".join([
                alert["rule"],
                alert["timestamp"],
                alert["source_ip"],
                alert["username"]
            ])

            alert_id = hashlib.sha256(
                identity.encode("utf-8")
            ).hexdigest()

            connection.execute("""
                INSERT OR IGNORE INTO alerts (
                    alert_id, rule, severity, timestamp,
                    source_ip, username, description, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'Open')
            """, (
                alert_id,
                alert["rule"],
                alert["severity"],
                alert["timestamp"],
                alert["source_ip"],
                alert["username"],
                alert["description"]
            ))


def get_alerts():
    """Return stored alerts, newest first."""
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("""
            SELECT * FROM alerts
            ORDER BY timestamp DESC
        """).fetchall()

        return [dict(row) for row in rows]


def update_alert_status(alert_id, status):
    """Update an alert's investigation status."""
    allowed_statuses = {"Open", "Investigating", "Resolved"}

    if status not in allowed_statuses:
        raise ValueError("Invalid investigation status")

    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.execute("""
            UPDATE alerts
            SET status = ?
            WHERE alert_id = ?
        """, (status, alert_id))

        return cursor.rowcount > 0
