from datetime import datetime
import database
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def parse_line(line):
    parts = line.split()
    if len(parts) != 5:
        return None
    date, event_time, event, user, ip = parts
    try:
        timestamp = datetime.strptime(f"{date} {event_time}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return{
        "timestamp": timestamp,
        "event": event,
        "user": user,
        "ip": ip
    }

def load_events(path):
    events = []
    malformed = 0
    with open(path) as f: 
        for line in f:
            entry = parse_line(line)
            if entry is None:
                malformed += 1
            else:
                events.append(entry)
    return events, malformed

def print_summary(events):
    total_events = len(events)
    failed_counts = 0
    targeted_users = []
    failure_times = {}

    for entry in events:
        if entry["event"] == "FAILED_LOGIN":
            ip = entry["ip"]
            failed_counts += 1
            if entry["user"] not in targeted_users:
                targeted_users.append(entry["user"])
            if ip not in failure_times:
                failure_times[ip] = []
            failure_times[ip].append(entry["timestamp"])

    print("=== LOG SUMMARY ===")
    print(f"Total Events:  {total_events}")
    print(f"Failed Logins:  {failed_counts}")
    print("Failures by IP:")

    for ip in sorted(failure_times, key=lambda ip: len(failure_times[ip]), reverse=True):
        stamps = failure_times[ip]
        earliest = min(stamps).strftime("%H:%M:%S")
        latest = max(stamps).strftime("%H:%M:%S")
        if earliest == latest:
            when = earliest
        else:
            when = f"{earliest} -> {latest}"
        print(f"  {ip:<15}{len(stamps)}  ({when})")

    print(f"Targeted users:   {', '.join(targeted_users)}")

#1
def detect_brute_force(events):
    times_by_ip = {}
    for entry in events:
        if entry["event"] == "FAILED_LOGIN":
            ip = entry["ip"]
            if ip not in times_by_ip:
                times_by_ip[ip] = []
            times_by_ip[ip].append(entry["timestamp"])

    alerts = []
    for ip, times in times_by_ip.items():
        times.sort()
        for i in range(len(times) - 4):
            window = (times[i + 4] - times[i]).total_seconds()
            if window <= 120:
                alerts.append({
                    "rule": "Brute force",
                    "severity": "HIGH",
                    "ip": ip,
                    "message": f"5 failures in {int(window)} seconds"
                })
                break
    return alerts


#2
def detect_username_spraying(events):
    users_by_ip = {}
    for entry in events:
        if entry["event"] == "FAILED_LOGIN":
            ip = entry["ip"]
            if ip not in users_by_ip:
                users_by_ip[ip] = []
            if entry["user"] not in users_by_ip[ip]:
                users_by_ip[ip].append(entry["user"])

    alerts = []
    for ip, users in users_by_ip.items():
        if len(users) >= 3:
            alerts.append({
                "rule": "Username spraying",
                "severity": "HIGH",
                "ip": ip,
                "message": f"tried {len(users)} usernames"
            })
    return alerts

#3
def detect_off_hours_logins(events):
    alerts = []
    for entry in events:
        if entry["event"] == "SUCCESS_LOGIN" and entry["timestamp"].hour < 5:
            alerts.append({
                "rule": "Off-hours login",
                "severity": "MEDIUM",
                "ip": entry["ip"],
                "message": f"login at {entry['timestamp'].strftime('%H:%M:%S')}" 
            })
    return alerts

#4
def detect_compromise(events):
    alerts = []
    for entry in events:
        if entry["event"] != "SUCCESS_LOGIN":
            continue
        recent_failures = 0
        for other in events:
            if (other["event"] == "FAILED_LOGIN"
                    and other["ip"] == entry["ip"]
                    and other["timestamp"] < entry["timestamp"]
                    and (entry["timestamp"] - other["timestamp"]).total_seconds() <= 120):
                recent_failures += 1
        if recent_failures >= 3:
            alerts.append({
                "rule": "Compromise",
                "severity": "CRITICAL",
                "ip": entry["ip"],
                "message": f"Successful after {recent_failures} failures"
            })
    return alerts

#5
def detect_malformed_logs(malformed):
    if malformed == 0:
        return []
    return [{
        "rule": "Malformed logs",
        "severity": "LOW",
        "ip": "—",
        "message": f"{malformed} line skipped" if malformed == 1 else f"{malformed} lines skipped"
    }]


def run_rules(events, malformed):
    alerts = []
    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_username_spraying(events))
    alerts.extend(detect_off_hours_logins(events))
    alerts.extend(detect_compromise(events))
    alerts.extend(detect_malformed_logs(malformed))
    return alerts


def sort_alerts(alerts):
    return sorted(alerts, key=lambda alert: SEVERITY_ORDER[alert["severity"]])


def print_alerts(alerts):
    print()
    print(f"=== ALERTS ({len(alerts)}) ===")
    if len(alerts) == 0:
        print("No alerts.")
        return
    for alert in sort_alerts(alerts):
        tag = f"[{alert['severity']}]"
        print(f"{tag:<11}{alert['rule']:<18}{alert['ip']:<14}{alert['message']}")


def main():
    conn = database.init_db("soc.db")
    
    events, malformed = load_events("logs/sample.log")
    print_summary(events)
    alerts = run_rules(events, malformed)
    print_alerts(alerts)

    conn.close()
main()
