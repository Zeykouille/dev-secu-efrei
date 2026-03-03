import re
import ipaddress
from datetime import datetime

REGEX_IP = re.compile(r"from (\S+)")
REGEX_FAILED = re.compile(r"Failed password for (invalid user )?(\w+)")
REGEX_SUCCESS = re.compile(r"Accepted (password|publickey) for (\w+)")
REGEX_INVALID = re.compile(r"Invalid user (\w+)")

def parse_line(line):
    try:
        timestamp = datetime.now()  # simplifié ici

        ip_match = REGEX_IP.search(line)
        if not ip_match:
            return None

        raw_ip = ip_match.group(1)

        # Validation IP réelle
        try:
            ip = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            return None

        if REGEX_FAILED.search(line):
            return ("failed", ip)

        if REGEX_SUCCESS.search(line):
            return ("success", ip)

        if REGEX_INVALID.search(line):
            return ("invalid", ip)

        return None

    except Exception:
        return None
