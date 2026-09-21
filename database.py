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
            UNIQUE (rule, source_ip)
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
        "INSERT INTO alerts (rule, severity, source_ip, message, detected_at) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (rule, source_ip) DO UPDATE SET "
        "severity = excluded.severity, message = excluded.message "
        "WHERE message != excluded.message OR severity != excluded.severity",
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

def count_events(conn):
    row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
    return row[0]

def count_alerts(conn):
    row = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
    return row[0]

def count_critical_alerts(conn):
    row = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = ?",
        ("CRITICAL",),
    ).fetchone()
    return row[0]

def get_recent_alerts(conn):
    rows = conn.execute(
        "SELECT rule, severity, source_ip, message, detected_at "
        "FROM alerts ORDER BY id DESC LIMIT 10"
    ).fetchall()

    alerts = []
    for rule, severity, source_ip, message, detected_at in rows:
        alerts.append({
            "rule": rule,
            "severity": severity,
            "source_ip": source_ip,
            "message": message,
            "detected_at": detected_at
        })
    return alerts

def get_top_ips(conn):
    rows = conn.execute(
        "SELECT source_ip, COUNT(*) FROM events "
        "WHERE event_type = ? "
        "GROUP BY source_ip "
        "ORDER BY COUNT(*) DESC, source_ip "
        "LIMIT 5",
        ("FAILED_LOGIN",),
    ).fetchall()

    top_ips = []
    for source_ip, count in rows:
        top_ips.append({
            "source_ip": source_ip,
            "count": count,
        })
    return top_ips
