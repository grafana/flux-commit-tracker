FROM --platform=${BUILDPLATFORM} golang:1.24.2-alpine3.21@sha256:7772cb5322baa875edd74705556d08f0eeca7b9c4b5367754ce3f2f00041ccee AS builder

WORKDIR /app

ARG TARGETOS TARGETARCH

ARG VERSION=unknown
ARG COMMIT=unknown
ARG BRANCH=unknown

RUN --mount=target=. \
  --mount=type=cache,target=/root/.cache/go-build \
  --mount=type=cache,target=/go/pkg/mod \
  GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOAMD64=v2 \
  go build \
  -trimpath \
  -ldflags="-s -w -X github.com/grafana/flux-commit-tracker/internal/buildinfo.Version=${VERSION} -X github.com/grafana/flux-commit-tracker/internal/buildinfo.Commit=${COMMIT} -X github.com/grafana/flux-commit-tracker/internal/buildinfo.Branch=${BRANCH}" \
  -o /usr/bin/flux-commit-tracker \
  ./cmd/main.go

FROM scratch

COPY <<EOF /etc/group
nogroup:x:65534:
EOF

COPY <<EOF /etc/passwd
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
EOF

USER nobody:nogroup

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/bin/flux-commit-tracker /usr/bin/flux-commit-tracker

ENTRYPOINT ["/usr/bin/flux-commit-tracker"]
