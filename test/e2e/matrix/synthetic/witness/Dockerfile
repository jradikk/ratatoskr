# Test-only independent VPN witness; parent/operator builds and imports locally.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends openvpn iproute2 python3 \
    && rm -rf /var/lib/apt/lists/*
COPY witness.py /usr/local/bin/witness.py
RUN chmod 0555 /usr/local/bin/witness.py
USER 0:0
ENTRYPOINT ["python3", "/usr/local/bin/witness.py"]
