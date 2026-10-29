# syntax=docker/dockerfile:1.7
# Build from the repository root; only this plugin is copied into the build.
ARG GO_VERSION=1.27.3
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-trixie AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY plugins/upstream/openvpn/ ./plugins/upstream/openvpn/
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w" -o /out/openvpn-upstream ./plugins/upstream/openvpn/cmd/openvpn

FROM debian:trixie-slim
# OpenVPN uses iproute2 internally for interface setup (script-security 1).
RUN apt-get update && apt-get install -y --no-install-recommends openvpn iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/ratatoskr && chmod 0700 /run/ratatoskr
LABEL org.opencontainers.image.source="https://github.com/skaldhall/ratatoskr" \
      org.opencontainers.image.title="ratatoskr-upstream-openvpn" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/openvpn-upstream /usr/local/bin/openvpn-upstream
USER 0:0
ENTRYPOINT ["/usr/local/bin/openvpn-upstream"]
