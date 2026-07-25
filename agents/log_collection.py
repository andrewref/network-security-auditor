"""
Log Collection Agent.

Responsible for pulling raw logs from `state["devices"]` and producing
a filtered/normalized list the Log Analysis Agent can work on.

`_collect_raw_logs` is the ONE integration point for real device
polling (syslog server, SSH pull, SNMP, etc). Swap its body for a real
collector; nothing else in the pipeline needs to change. For now it
returns a fixed demo log set so the pipeline is runnable end-to-end
without a lab network attached.
"""

import re
import socket
import threading
from collections import deque
from pathlib import Path

from state import AuditState

NOISE_PATTERNS = ["heartbeat", "keepalive"]

# Where lab/syslog_collector.py writes real router syslog (file-based fallback).
LAB_SYSLOG = Path(__file__).resolve().parent.parent / "lab_syslog.log"

# --- Live UDP syslog listener --------------------------------------------
# Binds UDP:5514 in a background thread and buffers real router syslog as it
# arrives. This is the LIVE feed: the routers forward here directly, so an
# attack shows up within seconds, no file and no clicking. RFC3164 priority
# header (<38>) is stripped so the line matches the Sigma rules.
SYSLOG_PORT = 5514
_PRI = re.compile(r"^<\d+>")
_live_buffer: deque[str] = deque(maxlen=5000)
_listener_thread: threading.Thread | None = None
_lock = threading.Lock()


def _listener_loop() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", SYSLOG_PORT))
    except OSError as e:
        print(f"[log_collection] cannot bind UDP {SYSLOG_PORT}: {e}")
        return
    while True:
        try:
            data, _ = sock.recvfrom(8192)
        except OSError:
            continue
        line = _PRI.sub("", data.decode("utf-8", "replace")).strip()
        if line:
            _live_buffer.append(line)


def ensure_listener() -> None:
    """Start the UDP listener if it isn't already alive. Idempotent, safe to
    call on every Streamlit rerun; re-spawns only if the thread died."""
    global _listener_thread
    with _lock:
        if _listener_thread is not None and _listener_thread.is_alive():
            return
        _listener_thread = threading.Thread(
            target=_listener_loop, name="syslog-listener", daemon=True
        )
        _listener_thread.start()


def live_packet_count() -> int:
    return len(_live_buffer)


def drain_live() -> list[str]:
    """Return everything received since the last drain and clear the buffer.
    Used by live monitoring so each cycle reflects THIS interval's real router
    traffic, not everything since the app started."""
    ensure_listener()
    out = list(_live_buffer)
    _live_buffer.clear()
    return out


def _collect_raw_logs(devices: list[str]) -> list[str]:
    """LIVE first: real syslog received over UDP this session. Then the lab
    file. Only if BOTH are empty do we fall back to demo data."""
    ensure_listener()
    if _live_buffer:
        return list(_live_buffer)

    if LAB_SYSLOG.exists():
        lines = [ln.strip() for ln in LAB_SYSLOG.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if lines:
            return lines

    return [
        "Jul 16 12:10:15 Router1 Failed password for admin from 192.168.1.100",
        "Jul 16 12:10:20 Router1 Failed password for admin from 192.168.1.100",
        "Jul 16 12:10:25 Router1 Failed password for admin from 192.168.1.100",
        "Jul 16 12:15:00 Switch1 Telnet service started",
        "Jul 16 12:20:00 Firewall Allowed SSH connection",
        "Jul 16 12:25:00 Router1 heartbeat ok",
    ]


def _devices_from_logs(raw_logs: list[str]) -> list[str]:
    """Host is the 4th token of an RFC3164 line: 'Mon DD HH:MM:SS <host> ...'.
    Returns the distinct routers that actually reported, in first-seen order."""
    seen = []
    for line in raw_logs:
        parts = line.split()
        if len(parts) >= 4 and parts[3] not in seen:
            seen.append(parts[3])
    return seen


def _filter_logs(raw_logs: list[str]) -> list[str]:
    """Drop noise lines, dedupe exact repeats aren't dropped on purpose --
    repeated auth failures are themselves a signal for log_analysis."""
    return [line for line in raw_logs if not any(noise in line for noise in NOISE_PATTERNS)]


def run(state: AuditState) -> AuditState:
    devices = state.get("devices", [])
    # Live mode hands us the exact syslog drained for this interval; use it
    # verbatim so the audit reflects only THIS minute's real router traffic.
    preloaded = state.get("preloaded_logs")
    raw_logs = preloaded if preloaded is not None else _collect_raw_logs(devices)
    filtered_logs = _filter_logs(raw_logs)

    # When real syslog is present, the reporting routers ARE the devices --
    # override whatever was passed so --devices matches the live lab.
    real_devices = _devices_from_logs(raw_logs)
    if real_devices:
        state["devices"] = real_devices

    state["raw_logs"] = raw_logs
    state["filtered_logs"] = filtered_logs
    state.setdefault("completed_agents", []).append("log_collection")
    return state
