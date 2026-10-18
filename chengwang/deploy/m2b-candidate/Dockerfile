# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY internal/probe/ ./internal/probe/
COPY deploy/m2b-candidate/cmd/candidate-guard/ ./deploy/m2b-candidate/cmd/candidate-guard/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/m2b-candidate-guard ./deploy/m2b-candidate/cmd/candidate-guard

FROM alpine:3.21
RUN addgroup -S -g 10001 chengwang-probe \
    && adduser -S -D -H -u 10001 -G chengwang-probe chengwang-probe \
    && mkdir -p /app /run/m2b /var/lib/chengwang-probe \
    && chown -R 10001:10001 /run/m2b /var/lib/chengwang-probe
COPY --from=builder /out/m2b-candidate-guard /app/m2b-candidate-guard
USER 10001:10001
WORKDIR /app
ENTRYPOINT ["/app/m2b-candidate-guard"]
CMD ["serve", "--catalog", "/run/chengwang-probe/catalog.json", "--spool", "/var/lib/chengwang-probe", "--health-file", "/run/m2b/health.json"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/m2b-candidate-guard", "health", "--health-file", "/run/m2b/health.json", "--max-age", "20s"]
