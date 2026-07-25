#!/bin/bash
# Control script for the 2-router Docker lab.
#
#   ./lab.sh up       build image + start Router-01 and Router-02
#   ./lab.sh attack   real failed-login brute-force against a router
#   ./lab.sh logs     show each router's recent sshd auth log
#   ./lab.sh reset    restart routers to a clean baseline (no attacks)
#   ./lab.sh down     stop and remove the routers
#
# Windows note: pass COLLECTOR_IP=host.docker.internal (hostname -I is Linux-only).
set -euo pipefail

IMAGE="lab-router"
NET="labnet"
ROUTERS=(Router-01 Router-02)
COLLECTOR_PORT="${COLLECTOR_PORT:-5514}"

# Auto-detect host IP on Linux; on Windows/Mac use host.docker.internal.
detect_ip() { hostname -I 2>/dev/null | awk '{print $1}'; }
COLLECTOR_IP="${COLLECTOR_IP:-$(detect_ip)}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

up() {
    [ -n "$COLLECTOR_IP" ] || { echo "Set COLLECTOR_IP (Windows: host.docker.internal)"; exit 1; }
    docker build -t "$IMAGE" "$here"
    docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"
    for r in "${ROUTERS[@]}"; do
        docker rm -f "$r" >/dev/null 2>&1 || true
        docker run -d --name "$r" --hostname "$r" --network "$NET" \
            --add-host host.docker.internal:host-gateway \
            -e ROUTER_NAME="$r" \
            -e COLLECTOR_IP="$COLLECTOR_IP" \
            -e COLLECTOR_PORT="$COLLECTOR_PORT" \
            "$IMAGE"
        echo "Started $r -> syslog to ${COLLECTOR_IP}:${COLLECTOR_PORT}"
    done
}

# Real brute-force: repeated ssh logins with wrong passwords -> genuine
# "Failed password" auth events, forwarded as syslog. ATTACK_USERS controls burst size.
attack() {
    local target="${1:-Router-01}"
    local users="${ATTACK_USERS:-2}"
    echo "Brute-forcing $target ($users user(s) x 5 attempts each)..."
    for u in $(seq 1 "$users"); do
        for _ in $(seq 1 5); do
            docker exec "$target" bash -c \
                "sshpass -p wrongpass ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 attacker${u}@localhost true" \
                2>/dev/null || true
        done
    done
    echo "Done. Run './lab.sh logs' or the auditor to see findings."
}

logs() {
    for r in "${ROUTERS[@]}"; do
        echo "===== $r auth.log ====="
        docker exec "$r" tail -n 20 /var/log/auth.log 2>/dev/null || echo "(none)"
        echo
    done
}

reset() {
    for r in "${ROUTERS[@]}"; do
        docker restart "$r" >/dev/null && echo "Reset $r to clean baseline"
    done
}

down() {
    for r in "${ROUTERS[@]}"; do docker rm -f "$r" >/dev/null 2>&1 || true; done
    docker network rm "$NET" >/dev/null 2>&1 || true
    echo "Lab stopped."
}

cmd="${1:-}"; shift || true
case "$cmd" in
    up)     up ;;
    attack) attack "$@" ;;
    logs)   logs ;;
    reset)  reset ;;
    down)   down ;;
    *) echo "Usage: $0 {up|attack|logs|reset|down}"; exit 1 ;;
esac
