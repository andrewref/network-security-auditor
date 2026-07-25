"""
Sigma-style rule matching + BERTLog integration point.

`analyze_logs` is deterministic and explainable on its own (the Sigma
half). It also enriches each brute-force finding with the real forensic
detail parsed straight from the log lines: attacker source IP(s), the
usernames tried, first/last-seen timestamps, attempt rate, sample
evidence lines, and whether any attempt actually SUCCEEDED (a breach).
The BERTLog half is a placeholder.
"""

import re

from langchain_core.tools import tool

# Parse the useful fields out of a real sshd line.
_IP_RE = re.compile(r"from (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+) port")
_USER_RE = re.compile(r"(?:invalid user |user |for )([A-Za-z0-9._-]+) from")
# The hostname token: RFC3164 'Mon DD HH:MM:SS <host> ...' (4th token) or
# ISO '2026-..T..:..:.. <host> ...' (2nd token). Match a host that is followed
# by a 'word:' syslog tag, which both formats share.
_HOST_RE = re.compile(r"(?:^\w{3}\s+\d+\s+[\d:]+|^\S+)\s+(\S+)\s+\S+?:")


def _device_of(log: str) -> str:
    """Router name, handling both RFC3164 and ISO-timestamp line formats."""
    m = _HOST_RE.match(log)
    if m:
        return m.group(1)
    parts = log.split()
    return parts[3] if len(parts) >= 4 else "unknown"


def _timestamp_of(log: str) -> str:
    """The timestamp portion: RFC3164 = first 3 tokens, ISO = first token."""
    parts = log.split()
    if len(parts) >= 3 and re.match(r"^\w{3}$", parts[0]):  # 'Jul 18 14:17:07'
        return " ".join(parts[:3])
    return parts[0] if parts else ""


def _ip_of(log: str) -> str | None:
    m = _IP_RE.search(log)
    return m.group(1) if m else None


def _user_of(log: str) -> str | None:
    m = _USER_RE.search(log)
    return m.group(1) if m else None


def _bertlog_predict(filtered_logs: list[str]) -> list[dict]:
    """
    Placeholder for the real trained BERTLog anomaly classifier.

    Real version:
        tokens = bertlog_preprocess(filtered_logs)
        return bertlog_model.predict(tokens)
    """
    return []


@tool
def analyze_logs(filtered_logs: list) -> dict:
    """
    Analyze network logs using Sigma rules and BERTLog.
    Returns all detected security events.
    """
    # One finding PER DEVICE per rule, enriched with real forensic detail
    # parsed from the log lines: attacker IPs, usernames tried, timing, rate,
    # sample evidence, and whether any login SUCCEEDED (breach).
    brute: dict[str, dict] = {}   # device -> evidence bundle
    telnet_devices: set[str] = set()
    success_by_device: dict[str, list[str]] = {}  # device -> accepted-login users

    for log in filtered_logs:
        device = _device_of(log)

        if "Failed password" in log:
            b = brute.setdefault(device, {
                "count": 0, "ips": set(), "users": set(),
                "timestamps": [], "samples": [],
            })
            b["count"] += 1
            ip = _ip_of(log)
            if ip:
                b["ips"].add(ip)
            user = _user_of(log)
            if user:
                b["users"].add(user)
            ts = _timestamp_of(log)
            if ts:
                b["timestamps"].append(ts)
            if len(b["samples"]) < 10:   # keep more proof lines per finding
                b["samples"].append(log.strip())

        # Real breach signal: a successful login. If it follows failures on the
        # same device, the brute force worked.
        if "Accepted password" in log or "Accepted publickey" in log:
            success_by_device.setdefault(device, []).append(_user_of(log) or "?")

        if "Telnet" in log:
            telnet_devices.add(device)

    sigma_results = []
    for device, b in brute.items():
        ts = sorted(b["timestamps"])
        first, last = (ts[0], ts[-1]) if ts else ("", "")
        ips = sorted(b["ips"])
        users = sorted(b["users"])
        breached = success_by_device.get(device)

        desc = (f"{b['count']} failed login attempt(s) on {device} "
                f"from {', '.join(ips) or 'unknown'}; "
                f"usernames tried: {', '.join(users) or 'unknown'}.")

        sigma_results.append({
            "title": "Brute Force",
            "device": device,
            "impact": 5 if breached else 4,     # a successful breach is worse
            "likelihood": 4,
            "description": desc,
            # --- forensic enrichment (real, parsed from the logs) ---
            "attempts": b["count"],
            "source_ips": ips,
            "usernames": users,
            "first_seen": first,
            "last_seen": last,
            "evidence": b["samples"],
            "breach": bool(breached),
            "breached_users": breached or [],
        })
    for device in telnet_devices:
        sigma_results.append({
            "title": "Telnet Enabled",
            "device": device,
            "impact": 3,
            "likelihood": 5,  # cleartext protocol actively running = high certainty
            "description": f"Insecure remote access service detected on {device}.",
        })

    bertlog_results = _bertlog_predict(filtered_logs)

    return {
        "sigma_results": sigma_results,
        "bertlog_results": bertlog_results,
    }
