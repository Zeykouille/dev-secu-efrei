from collections import defaultdict, deque
from datetime import timedelta, datetime
from config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_MINUTES

failed_by_ip = defaultdict(lambda: deque(maxlen=1000))
alerted_ips = set()

def process_event(event):
    event_type, ip = event

    if event_type == "failed":
        failed_by_ip[ip].append(datetime.now())
        check_bruteforce(ip)

def check_bruteforce(ip):
    timestamps = failed_by_ip[ip]
    now = datetime.now()

    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)

    count = sum(1 for t in timestamps if now - t <= window)

    if count >= BRUTE_FORCE_THRESHOLD:
        if ip not in alerted_ips:
            print(f"[ALERT] Possible brute force from {ip}")
            alerted_ips.add(ip)
