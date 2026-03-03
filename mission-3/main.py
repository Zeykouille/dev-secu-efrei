import re
from datetime import datetime, timedelta
from collections import defaultdict

internal_networks = ["10.", "172.18."]

def is_internal_ip(ip):
    return any(ip.startswith(net) for net in internal_networks)

log_pattern = re.compile(
    r"\[(?P<timestamp>[\d\-T:]+Z)\]\s*"
    r"(?P<user>[^|]+)\s*\|\s*(?P<role>[^|]+)\s*\|\s*"
    r"(?P<ip>[^|]+)\s*\|\s*(?P<app>[^|]+)\s*\|\s*"
    r"(?P<action>[^|]+)\s*\|\s*(?P<resource>[^|]+)\s*\|\s*"
    r"(?P<query_count>[^|]+)\s*\|\s*(?P<status>[^|]+)\s*\|\s*"
    r"(?P<mfa>[^|]+)\s*\|\s*(?P<session_id>[^|\s]+)"
)

def parse_line(line):
    match = log_pattern.match(line)
    if not match:
        return None
    d = match.groupdict()
    try:
        d["timestamp"] = datetime.fromisoformat(d["timestamp"].replace('Z', '+00:00'))
        d["query_count"] = int(d["query_count"]) if d["query_count"].isdigit() else 0
    except:
        return None
    return d

def analyze_logs(file_path):
    sessions = defaultdict(list)
    anomalies = []

    with open(file_path, "r") as f:
        text = f.read().replace("\n", " ") 

    for log_text in re.findall(r"\[[\d\-T:]+Z\][^\[]*", text):
        log = parse_line(log_text.strip())
        if not log:
            continue
        sessions[log["session_id"]].append(log)

        if not is_internal_ip(log["ip"]):
            anomalies.append((log, "IP externe suspecte"))
        if log["mfa"] in ["MFA_FAIL", "MFA_BYPASS"]:
            anomalies.append((log, "Problème MFA"))
        if log["timestamp"].hour < 6 or log["timestamp"].hour > 20:
            anomalies.append((log, "Accès hors horaires"))

    for session_id, logs in sessions.items():
        logs_sorted = sorted(logs, key=lambda x: x["timestamp"])
        for i in range(len(logs_sorted)):
            cumulative = logs_sorted[i]["query_count"]
            start_time = logs_sorted[i]["timestamp"]
            for j in range(i+1, len(logs_sorted)):
                diff = (logs_sorted[j]["timestamp"] - start_time).total_seconds()
                if diff > 10:
                    break
                cumulative += logs_sorted[j]["query_count"]
            if cumulative > 50:
                anomalies.append((logs_sorted[i], f"Rafale rapide ou volume élevé ({cumulative} requêtes)"))
        for log in logs_sorted:
            if log["action"] == "EXPORT" and log["query_count"] > 1000:
                anomalies.append((log, f"Extraction massive ({log['query_count']} lignes)"))

    return anomalies

file_path = "ficoba_logs.txt"
alerts = analyze_logs(file_path)

print(f"Nombre de logs analysés : {len(alerts)}\n")
for log, reason in alerts:
    print(f"{log['timestamp']} | {log['user']} | {reason} | {log['ip']} | {log['action']} | {log['query_count']} | Session: {log['session_id']}")
    