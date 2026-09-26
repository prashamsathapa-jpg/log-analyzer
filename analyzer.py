import re
from datetime import datetime
from collections import defaultdict

LOG_FILE = "sample_auth.log"
FAILED_ATTEMPT_THRESHOLD = 3   # flag if this many or more attempts happen...
TIME_WINDOW_MINUTES = 5        # ...within this many minutes

def parse_log(filename):
    """Reads the log file and extracts failed login attempts with timestamps."""
    failed_attempts = []
    pattern = r"^(\w+ \d+ \d+:\d+:\d+).*Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)"

    with open(filename, "r") as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group(1)
                username = match.group(2)
                ip = match.group(3)

                # Log has no year, so we assume the current year
                timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")

                failed_attempts.append({
                    "time": timestamp,
                    "username": username,
                    "ip": ip
                })

    return failed_attempts

def group_by_ip(failed_attempts):
    """Groups all failed attempts by IP, keeping their timestamps."""
    grouped = defaultdict(list)
    for attempt in failed_attempts:
        grouped[attempt["ip"]].append(attempt["time"])
    return grouped

def detect_bursts(timestamps, threshold, window_minutes):
    """
    Checks if 'threshold' or more attempts happened within 'window_minutes'
    of each other, using a sliding window over sorted timestamps.
    """
    timestamps = sorted(timestamps)
    window_seconds = window_minutes * 60

    for i in range(len(timestamps)):
        window_end = timestamps[i]
        count = 0
        for t in timestamps:
            if 0 <= (window_end - t).total_seconds() <= window_seconds:
                count += 1
        if count >= threshold:
            return True, count
    return False, 0

def main():
    failed_attempts = parse_log(LOG_FILE)
    print(f"Total failed login attempts found: {len(failed_attempts)}\n")

    grouped = group_by_ip(failed_attempts)

    print(f"Checking for {FAILED_ATTEMPT_THRESHOLD}+ failed attempts within {TIME_WINDOW_MINUTES} minutes:\n")
    any_suspicious = False
    for ip, timestamps in grouped.items():
        is_burst, count = detect_bursts(timestamps, FAILED_ATTEMPT_THRESHOLD, TIME_WINDOW_MINUTES)
        if is_burst:
            any_suspicious = True
            print(f"  🚨 SUSPICIOUS: {ip} — {count} failed attempts within {TIME_WINDOW_MINUTES} min (possible brute force)")
        else:
            print(f"  OK: {ip} — {len(timestamps)} failed attempt(s), not within threshold window")

    if not any_suspicious:
        print("\nNo brute-force patterns detected.")

if __name__ == "__main__":
    main()
