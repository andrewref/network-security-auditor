FROM debian:12-slim

# Real network-device services: FRRouting (routing), OpenSSH (auth), rsyslog (forwarding).
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        frr openssh-server rsyslog iproute2 procps sshpass && \
    rm -rf /var/lib/apt/lists/*

# Lab-only throwaway root password. Override: --build-arg ROOT_PASSWORD=...
ARG ROOT_PASSWORD=R0uter-lab!
RUN echo "root:${ROOT_PASSWORD}" | chpasswd && \
    mkdir -p /run/sshd && \
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

COPY start-router.sh /start-router.sh
RUN chmod +x /start-router.sh

CMD ["/start-router.sh"]
