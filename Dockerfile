FROM --platform=${BUILDPLATFORM} golang:1.27.3-alpine3.24@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder

WORKDIR /app

RUN apk add --no-cache 'ca-certificates>=20261020-r0' 'ca-certificates-bundle>=20261020-r0' \
  && update-ca-certificates

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
