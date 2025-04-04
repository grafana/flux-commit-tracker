FROM --platform=${BUILDPLATFORM} golang:1.24.2-alpine3.21 AS builder

WORKDIR /app

ARG TARGETOS TARGETARCH

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOAMD64=v2 \
    go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /usr/bin/flux-commit-tracker \
      ./cmd/main.go

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/bin/flux-commit-tracker /usr/bin/flux-commit-tracker

ENTRYPOINT ["/usr/bin/flux-commit-tracker"]
