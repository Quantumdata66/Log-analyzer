"""Simple Apache log analyzer.

This script prints basic counts (statuses, top IPs, 404s) and flags burst traffic
(>30 requests from the same IP in any 60-second window).
"""

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

LOG_PATH = "apache_logs.txt"
BURST_THRESHOLD = 30  # >30 requests
BURST_WINDOW = timedelta(seconds=60)
suspicious_path = {
    "wp-login", "phpmyadmin", "administrator",
    ".env", "xmlrpc", "admin", "config", "login"
}

timestamp_re = re.compile(r"\[(?P<ts>[^\]]+)\]")

with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as file:
    lines = file.readlines()

print("Total log entries:", len(lines))

print("\nFirst 5 lines:\n")
for line in lines[:5]:
    print(line.strip())

status_codes = []
errors_404 = Counter()
ip_suspicious = Counter()
ip_timestamps = defaultdict(list)
# track request paths per IP for later analysis
ip_paths = defaultdict(Counter)

for line in lines:
    parts = line.split()
    if len(parts) < 9:
        continue

    ip = parts[0]
    status = parts[8]

    status_codes.append(status)

    if status == "404":
        errors_404[ip] += 1

    # extract request path from quoted request section
    path_match = re.search(r'"[A-Z]+\s+([^\s]+)\s+HTTP/[0-9.]+"', line)
    if path_match:
       path = path_match.group(1)
       path_lower = path.lower()
       ip_paths[ip][path] += 1                  
       if any(keyword in path_lower for keyword in suspicious_path):
        ip_suspicious[ip] += 1               

    match = timestamp_re.search(line)
    if not match:
        continue

    ts_str = match.group("ts")
    try:
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        continue

    ip_timestamps[ip].append(dt)

counter = Counter(status_codes)

print("\nStatus Code Counts:")
for code, count in counter.items():
    print(code, count)

ip_counter = Counter({ip: len(ts_list) for ip, ts_list in ip_timestamps.items()})

print("\nMost Active IP Address:")
if ip_counter:
    most_active_ip, count = ip_counter.most_common(1)[0]
    print(f"{most_active_ip}: {count} requests")
else:
    print("No IP addresses found.")

print("\nTop 10 IP Addresses:")
for ip, count in ip_counter.most_common(10):
    print(f"{ip}: {count} requests")

print("\n[!] FLAGGED: IP Addresses with >300 Requests:")
flagged_ips = [(ip, count) for ip, count in ip_counter.items() if count > 300]
if flagged_ips:
    for ip, count in sorted(flagged_ips, key=lambda x: x[1], reverse=True):
        print(f"[!] {ip}: {count} requests")
else:
    print("No IP addresses with more than 300 requests found.")

print("\n! FLAGGED: IP Addresses with >20 404 Errors:")
flagged_404 = [(ip, count) for ip, count in errors_404.items() if count > 20]
if flagged_404:
    for ip, count in sorted(flagged_404, key=lambda x: x[1], reverse=True):
        print(f"! {ip}: {count} 404 errors")
else:
    print("No IP addresses with more than 20 404 errors found.")

# helper to print top requested paths for a set of IPs
def print_top_paths(title, ips):
    print(f"\n{title}:")
    if not ips:
        print("  (none)")
        return
    for ip in ips:
        print(f"  {ip}:")
        for path, cnt in ip_paths[ip].most_common(5):
            print(f"    {path}: {cnt}")


def find_bursts(timestamps, threshold=BURST_THRESHOLD, window=BURST_WINDOW):
    """Return list of (start, end, count) for DISTINCT bursts > threshold within window."""
    if not timestamps:
        return []

    timestamps = sorted(timestamps)
    bursts = []
    start = 0
    in_burst = False

    for end in range(len(timestamps)):
        while timestamps[end] - timestamps[start] > window:
            start += 1

        count = end - start + 1
        if count > threshold:
            if not in_burst:
                burst_start = timestamps[start]
                in_burst = True
            burst_end = timestamps[end]
            burst_count = count
        else:
            if in_burst:
                bursts.append((burst_start, burst_end, burst_count))
            in_burst = False

    if in_burst:
        bursts.append((burst_start, burst_end, burst_count))

    return bursts

# compute bursts before reporting paths

print("\n Burst Traffic (>{} reqs in 60s):".format(BURST_THRESHOLD))
any_bursts = False
ip_bursts = {}

for ip,  ts_list in ip_timestamps.items():
    bursts = find_bursts(ts_list)
    if not bursts:
        continue

    ip_bursts[ip] = bursts
    any_bursts = True
    print(f"\nIP {ip} has {len(bursts)} burst(s):")
    for start, end, count in bursts[:5]:
        print(f"  {start.isoformat()} -> {end.isoformat()} ({count} reqs)")
    if len(bursts) > 5:
        print(f"  ...and {len(bursts) - 5} more bursts")

if not any_bursts:
    print("No burst traffic detected.")

# report top paths for various flagged groups

flagged_ip_list = [ip for ip, _ in flagged_ips]
flagged_404_list = [ip for ip, _ in flagged_404]
burst_multi = [ip for ip, bursts in ip_bursts.items() if len(bursts) > 1]

print_top_paths("Top paths for IPs with >300 requests", flagged_ip_list)
print_top_paths("Top paths for IPs with >20 404 errors", flagged_404_list)
print_top_paths("Top paths for IPs with multiple bursts", burst_multi)

print("\n[!] FLAGGED: IPs probing suspicious paths:")
flagged_suspicious = [(ip, count) for ip, count in ip_suspicious.items() if count > 1]
if flagged_suspicious:
    for ip, count in sorted(flagged_suspicious, key=lambda x: x[1], reverse=True):
        print(f"[!] {ip}: {count} suspicious path hits")
        for path, cnt in ip_paths[ip].most_common(1):
            if any(k in path for k in suspicious_path):
                print(f"     {path}: {cnt}")
else:
    print("No suspicious path probing detected.")

# --- IP classification ---
def classify_ip(ip, ts_list, paths_counter, errors_404_count,known_reverse_dns, bursts,ip_suspicious_count =0):
    """Classify an IP into one of four labels:
    'benign crawler', 'aggressive bot', 'stale fetcher', 'needs investigation'.
    Using simple heuristics based on request counts, path variety, 404s and bursts.
    """

    total = len(ts_list)
    unique_paths = len(paths_counter)

    if total == 0:
        return "needs investigation"

    # compute active window in minutes (avoid zero)
    span = (max(ts_list) - min(ts_list)).total_seconds() / 60.0 if len(ts_list) > 1 else 0.001
    rpm = total / span if span > 0 else float("inf")

    max_burst = 0
    for b in bursts:
        if len(b) >= 3:
            max_burst = max(max_burst, b[2])

    # Heuristics (tunable):
    # aggressive bot: very large bursts or huge total requests or many 404s
    if ip_suspicious_count > 1:
        return "aggressive bot"

    if max_burst > 100 or total > 3000 or errors_404_count > 200:
        return "aggressive bot"

    # benign crawler: many requests, wide path coverage, few bursts and few 404s
    if total > 500 and unique_paths > 100 and len(bursts) == 0 and errors_404_count < 20:
        return "benign crawler"

    # stale fetcher: repeated requests but low path variety (e.g., polling same resources)
    if total > 100 and unique_paths <= 5 and errors_404_count < 50 and rpm < 20:
        return "stale fetcher"
    
    #  Aggressive fetcher: high request but no suspicious paths, but many bursts and 404s
    if total > 200 and unique_paths > 50 and errors_404_count < 20:
        return "aggressive fetcher"

    # needs investigation: anything not classified above
    return "needs investigation"


print("\nIP Classification Summary:")
labels = defaultdict(list)

# manual overrides: (ip -> (label, reason))
manual_overrides = {
    "66.249.73.135": (
        "benign crawler",
        "feed-heavy paths and known Googlebot reverse DNS",
    ),
    "208.91.156.11": (
        "stale fetcher",
        "60 repeated 404s on a single missing jar file",
    ),
    "130.237.218.86": (
        "needs investigation",
        "6 burst windows and 208 unique paths, but no clear admin-probing pattern",
    ),
}
known_reverse_dns = {
    "66.249.73.135": "crawl-66-249-73-135.googlebot.com",
}

for ip, ts_list in ip_timestamps.items():
    bursts = ip_bursts.get(ip, [])
    paths_counter = ip_paths.get(ip, Counter())
    errors_count = errors_404.get(ip, 0)

    if ip in manual_overrides:
        label, reason = manual_overrides[ip]
    else:
        label = classify_ip(
    ip,
    ts_list,
    paths_counter,
    errors_count,
    bursts,
    known_reverse_dns.get(ip, ""),
    ip_suspicious.get(ip, 0)
   )
        reason = None

    labels[label].append((ip, len(ts_list), errors_count, len(paths_counter), len(bursts), reason))

for label in ["benign crawler", "aggressive bot", "stale fetcher", "needs investigation"]:
    group = labels.get(label, [])
    print(f"\n{label} ({len(group)}):")
    if not group:
        print("  (none)")
        continue
    # show top 10 by request count
    for ip, total, errs, upaths, bcount, reason in sorted(group, key=lambda x: x[1], reverse=True)[:10]:
        line = f"  {ip}: {total} reqs, {errs} 404s, {upaths} unique paths, {bcount} bursts"
        if reason:
            line += f"  -- Reason: {reason}"
        print(line)

