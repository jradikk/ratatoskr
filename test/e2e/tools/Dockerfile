# syntax=docker/dockerfile:1.7
# Test-only client/tools image. Not a production workload or release image.
ARG GO_VERSION=1.27.3
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-trixie AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd/init/ ./cmd/init/
COPY api/ ./api/
COPY pkg/ ./pkg/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w" -o /out/ratatoskr-init ./cmd/init
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl jq iproute2 nftables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ratatoskr-init /ratatoskr-init
USER 0:0
CMD ["sleep", "infinity"]
