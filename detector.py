from datetime import datetime

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
    failures_byIP = {}
    targeted_users = []
    failure_times = {}

    for entry in events:
        if entry["event"] == "FAILED_LOGIN":
            ip = entry["ip"]
            failed_counts += 1
            failures_byIP[ip] = failures_byIP.get(ip, 0) + 1
            if entry["user"] not in targeted_users:
                targeted_users.append(entry["user"])
            if ip not in failure_times:
                failure_times[ip] = []
            failure_times[ip].append(entry["timestamp"])
    print("=== LOG SUMMARY ===")
    print(f"Total Events:  {total_events}")
    print(f"Failed Logins:  {failed_counts}")
    print("Failures by IP:")

    for ip in sorted(failures_byIP, key=failures_byIP.get, reverse=True):
        stamps = failure_times[ip]
        earliest = min(stamps).strftime("%H:%M:%S")
        latest = max(stamps).strftime("%H:%M:%S")
        if earliest == latest:
            when = earliest
        else:
            when = f"{earliest} -> {latest}"
        print(f"  {ip:<15}{failures_byIP[ip]}  ({when})")

    print(f"Targeted users:   {', '.join(targeted_users)}")


events, malformed = load_events("logs/sample.log")
print_summary(events)