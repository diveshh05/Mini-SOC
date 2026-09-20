import sqlite3

conn = sqlite3.connect("soc.db")
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
print(cur.fetchall())
conn.close()


def init_db(path):
    conn = sqlite3.connect(path)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT NOT NULL,
            source_ip TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            rule TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            message TEXT NOT NULL,
            detected_at TEXT NOT NULL
        )
    """)

    conn.commit()
    return conn
