import sqlite3
from datetime import datetime

def init_db(path):
    conn = sqlite3.connect(path)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            UNIQUE (timestamp, event_type, username, source_ip)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            rule TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            message TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            UNIQUE (rule, severity, source_ip, message)
        )
    """)

    conn.commit()
    return conn

def save_events(conn, events):
    rows = []
    for event in events:
        rows.append((
            event["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            event["event_type"],
            event["username"],
            event["source_ip"],
        ))

    cursor = conn.executemany(
        "INSERT OR IGNORE INTO events (timestamp, event_type, username, source_ip) VALUES (?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    return cursor.rowcount

def save_alerts(conn, alerts):
    detected_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = []
    for alert in alerts:
        rows.append((
            alert["rule"],
            alert["severity"],
            alert["source_ip"],
            alert["message"],
            detected_at,
        ))

    cursor = conn.executemany(
        "INSERT OR IGNORE INTO alerts (rule, severity, source_ip, message, detected_at) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    return cursor.rowcount

def load_events_from_db(conn):
    rows = conn.execute(
        "SELECT timestamp, event_type, username, source_ip FROM events ORDER BY id"
    ).fetchall()

    events = []
    for timestamp, event_type, username, source_ip in rows:
        events.append({
            "timestamp": datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S"),
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip,
        })
    return events

def load_alerts_from_db(conn):
    rows = conn.execute(
        "SELECT rule, severity, source_ip, message, detected_at FROM alerts ORDER BY id"
    ).fetchall()

    alerts = []
    for rule, severity, source_ip, message, detected_at in rows:
        alerts.append({
            "rule": rule,
            "severity": severity,
            "source_ip": source_ip,
            "message": message,
            "detected_at": datetime.strptime(detected_at, "%Y-%m-%d %H:%M:%S"),
        })
    return alerts
