# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.27.3
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-trixie AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY test/e2e/ci/fakeupstream/ ./test/e2e/ci/fakeupstream/
COPY plugins/upstream/openvpn/ ./plugins/upstream/openvpn/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w" -o /out/fakeupstream ./test/e2e/ci/fakeupstream
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/fakeupstream /fakeupstream
USER 0:0
ENTRYPOINT ["/fakeupstream"]
