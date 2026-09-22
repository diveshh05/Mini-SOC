import os
from datetime import datetime

from flask import Flask, render_template

import database

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "soc.db")

app = Flask(__name__)


@app.route("/")
def home():
    conn = database.init_db(DB_PATH)
    try:
        total_events = database.count_events(conn)
        total_alerts = database.count_alerts(conn)
        critical_alerts = database.count_critical_alerts(conn)
        recent_alerts = database.get_recent_alerts(conn)
    finally:
        conn.close()

    last_updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return render_template(
        "dashboard.html",
        total_events=total_events,
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        recent_alerts=recent_alerts,
        last_updated=last_updated,
    )