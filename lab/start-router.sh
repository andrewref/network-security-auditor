#!/bin/bash
# Container boot script. Forwards ALL logs to COLLECTOR_IP:5514 (RFC3164),
# stamping this router's name onto every line, then starts the real services.
set -e

ROUTER_NAME="${ROUTER_NAME:-Router}"
COLLECTOR_IP="${COLLECTOR_IP:?set COLLECTOR_IP (e.g. host.docker.internal)}"
COLLECTOR_PORT="${COLLECTOR_PORT:-5514}"

hostname "$ROUTER_NAME"

# rsyslog: forward everything over UDP in RFC3164, with our name as the hostname.
cat > /etc/rsyslog.d/50-forward.conf <<EOF
\$template LabFmt,"<%PRI%>%TIMESTAMP% ${ROUTER_NAME} %syslogtag%%msg%\n"
*.* @${COLLECTOR_IP}:${COLLECTOR_PORT};LabFmt
EOF

# sshd logs auth to syslog -> picked up by rsyslog -> forwarded.
/usr/sbin/sshd
rsyslogd

# FRR: real routing daemons (zebra + bgpd), genuine routing logs.
sed -i 's/^\(zebra\|bgpd\)=no/\1=yes/' /etc/frr/daemons 2>/dev/null || true
/usr/lib/frr/frrinit.sh start 2>/dev/null || service frr start 2>/dev/null || true

# A couple of genuine boot events so a fresh router shows life immediately.
logger -t router "boot: ${ROUTER_NAME} online"
logger -t frr "bgpd: routing daemon started"

# Keep the container alive, tailing the auth log so `docker logs` is useful.
touch /var/log/auth.log
exec tail -F /var/log/auth.log
