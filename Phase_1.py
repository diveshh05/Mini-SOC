total_events = 0 
failed_counts = 0
failures_byIP = {}
targeted_users = []
failure_times = {}

with open("logs/sample.log") as f:
    for line in f:
        parts = line.split()
        if len(parts) != 5:
            continue
        date, event_time, event, user, ip = parts
        total_events += 1
        if event == "FAILED_LOGIN":
            failed_counts += 1
            failures_byIP[ip] = failures_byIP.get(ip, 0) + 1
            if user not in targeted_users:
                targeted_users.append(user)
            if ip not in failure_times:
                failure_times[ip] = []
            failure_times[ip].append(f"{date} {event_time}")

print("=== LOG SUMMARY ===")
print(f"Total Events:  {total_events}")
print(f"Failed Logins:  {failed_counts}")
print(f"Failures by IP:")

for ip in sorted(failures_byIP, key=failures_byIP.get, reverse=True):
    stamps = failure_times[ip]
    earliest = min(stamps).split()[1]
    latest = max(stamps).split()[1]
    if earliest == latest:
        when = earliest
    else:
        when = f"{earliest} -> {latest}"
    print(f"  {ip:<15}{failures_byIP[ip]}  ({when})")

print(f"Targeted users:   {', '.join(targeted_users)}")