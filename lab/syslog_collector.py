"""
Syslog collector for the router lab.

Listens on UDP 5514, strips the RFC3164 priority/timestamp header, and
appends each received line to lab_syslog.log. Run this in one terminal
while the lab routers are up; then run `python app.py` in another.

    python lab/syslog_collector.py

Ctrl-C to stop. The auditor reads the same lab_syslog.log (see
agents/log_collection.py).
"""

import re
import socket
from pathlib import Path

HOST, PORT = "0.0.0.0", 5514
LOG_FILE = Path(__file__).resolve().parent.parent / "lab_syslog.log"

# <PRI>Mon DD HH:MM:SS host tag msg  ->  keep from "Mon DD..." onward.
_HEADER = re.compile(r"^<\d+>")


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"Listening on udp/{PORT}, writing to {LOG_FILE}")
    with LOG_FILE.open("a", encoding="utf-8") as f:
        while True:
            data, _ = sock.recvfrom(8192)
            line = _HEADER.sub("", data.decode("utf-8", "replace")).strip()
            if line:
                f.write(line + "\n")
                f.flush()
                print(line)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
