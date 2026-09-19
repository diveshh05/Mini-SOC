total = 0
count = 0
counts = {}
users = set()
times = {}
with open("logs/sample.log") as f:
    for line in f:
        date, time, event, user, ip = line.split()
        total += 1
        if event == "FAILED_LOGIN":
            count += 1
            counts[ip] = counts.get(ip, 0) + 1
            users.add(user)
            if ip not in times:
                times[ip] = []
            times[ip].append(time)

print("=== LOG SUMMARY ===")
print(f"Total events: {total}")
print(f"Failed logins: {count}")

print("Failure by IP: ")
for ip in sorted(counts, key=counts.get, reverse=True):
    first = times[ip][0]
    last = times[ip][-1]
    if first == last:
        when = first
    else:
        when = f"{first} -> {last}"
    print(f"  {ip:<15}{counts[ip]}  ({when})")

print(f"Targeted users:   {', '.join(users)}")