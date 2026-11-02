# Locally built test-only restricted one-shot client; never pulls in the gate.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 iproute2 ca-certificates libc-bin \
    && rm -rf /var/lib/apt/lists/*
COPY check.py /usr/local/bin/check.py
RUN chmod 0555 /usr/local/bin/check.py
USER 65532:65532
ENTRYPOINT ["python3", "/usr/local/bin/check.py"]
