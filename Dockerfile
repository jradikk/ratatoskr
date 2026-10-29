# syntax=docker/dockerfile:1.7
# Builds one Ratatoskr component image: controller, webhook, agent, gateway or init.
#   docker buildx build --build-arg COMPONENT=gateway --platform linux/amd64,linux/arm64 .
# Go is cross-compiled on the build platform; the runtime image is distroless/static.

ARG GO_VERSION=1.27.3

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-trixie AS build
ARG TARGETOS
ARG TARGETARCH
ARG COMPONENT
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    test -n "${COMPONENT}" && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
      -ldflags "-s -w -X github.com/skaldhall/ratatoskr/pkg/version.Version=${VERSION} -X github.com/skaldhall/ratatoskr/pkg/version.Commit=${COMMIT}" \
      -o /out/ratatoskr ./cmd/${COMPONENT}

FROM gcr.io/distroless/static-debian13:nonroot
ARG COMPONENT
LABEL org.opencontainers.image.source="https://github.com/skaldhall/ratatoskr" \
      org.opencontainers.image.title="ratatoskr-${COMPONENT}" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/ratatoskr /ratatoskr
ENTRYPOINT ["/ratatoskr"]
