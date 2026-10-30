# Local-only final-gate synthetic VPN server. Build from repository root:
# docker build -t ratatoskr-synthetic-openvpn:local test/e2e/matrix/synthetic/server
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends openvpn iproute2 python3 \
    && rm -rf /var/lib/apt/lists/*
COPY serve.py /usr/local/bin/serve.py
COPY start.sh /usr/local/bin/start.sh
RUN chmod 0555 /usr/local/bin/serve.py /usr/local/bin/start.sh
USER 0:0
ENTRYPOINT ["/usr/local/bin/start.sh"]
