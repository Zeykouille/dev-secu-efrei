#!/usr/bin/env python3

import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta

LOG_FILE = "auth.log"

BRUTE_FORCE_THRESHOLD = 10              # Nombre de tentatives
BRUTE_FORCE_WINDOW_MINUTES = 2          # Fenêtre temporelle en minutes

# Extraction d'adresse IP
REGEX_IP = re.compile(r"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")

# Détection utilisateur invalide
REGEX_INVALID_USER = re.compile(r"Invalid user (\w+)")

# Détection échec authentification
REGEX_FAILED = re.compile(r"Failed password for (invalid user )?(\w+)")

# Détection connexion réussie
REGEX_SUCCESS = re.compile(r"Accepted (password|publickey) for (\w+)")

# Détection mécanisme anti-bruteforce SSH (MaxStartups / throttling)
REGEX_MAXSTARTUPS = re.compile(r"MaxStartups|throttling|drop connection")


failed_attempts = []          
success_logins = []            
invalid_users = Counter()      
failed_by_ip = Counter()    
failed_by_user = Counter()    
events_by_ip = defaultdict(list) 
maxstartups_events = []         


def parse_timestamp(line):
    """
    Extrait le timestamp ISO présent au début de la ligne.
    Si le format n'est pas valide, retourne None.
    """
    try:
        return datetime.fromisoformat(line.split(" ")[0])
    except:
        return None

with open(LOG_FILE, "r", encoding="utf-8") as f:
    for line in f:

        timestamp = parse_timestamp(line)
        if not timestamp:
            continue

        ip_match = REGEX_IP.search(line)
        if ip_match:
            ip = ip_match.group(1)
            events_by_ip[ip].append(timestamp)

        failed_match = REGEX_FAILED.search(line)
        if failed_match and ip_match:
            user = failed_match.group(2)

            failed_attempts.append((timestamp, ip, user))

            failed_by_ip[ip] += 1
            failed_by_user[user] += 1


        invalid_match = REGEX_INVALID_USER.search(line)
        if invalid_match:
            invalid_users[invalid_match.group(1)] += 1

        success_match = REGEX_SUCCESS.search(line)
        if success_match and ip_match:
            user = success_match.group(2)
            success_logins.append((timestamp, ip, user))

        if REGEX_MAXSTARTUPS.search(line):
            maxstartups_events.append(line.strip())

print("\n================= GLOBAL STATS =================")
print(f"Total failed attempts: {len(failed_attempts)}")
print(f"Total successful logins: {len(success_logins)}")
print(f"Unique attacking IPs: {len(failed_by_ip)}")


print("\n================= TOP ATTACKING IPs =================")
for ip, count in failed_by_ip.most_common(10):
    print(f"{ip} -> {count} failed attempts")


print("\n================= TOP TARGETED USERS =================")
for user, count in failed_by_user.most_common(10):
    print(f"{user} -> {count} failed attempts")


print("\n================= INVALID USER ATTEMPTS =================")
for user, count in invalid_users.most_common(10):
    print(f"{user} -> {count} attempts")


print("\n================= SUCCESSFUL LOGINS =================")
for ts, ip, user in success_logins:
    print(f"{ts} - {user} from {ip}")


print("\n================= BRUTE FORCE DETECTION =================")

for ip, timestamps in events_by_ip.items():
    timestamps.sort()

    for i in range(len(timestamps)):
        window_start = timestamps[i]
        window_end = window_start + timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)

        count = sum(1 for t in timestamps if window_start <= t <= window_end)
        if count >= BRUTE_FORCE_THRESHOLD:
            print(f"Possible brute force from {ip} ({count} attempts in {BRUTE_FORCE_WINDOW_MINUTES} minutes)")
            break


print("\n================= FIRST / LAST SEEN PER IP =================")
for ip, timestamps in events_by_ip.items():
    print(f"{ip} -> first: {min(timestamps)} | last: {max(timestamps)} | total events: {len(timestamps)}")

if maxstartups_events:
    print("\n================= MAXSTARTUPS / THROTTLING DETECTED =================")
    for event in maxstartups_events:
        print(event)

print("\n================= ANALYSIS COMPLETE =================")
