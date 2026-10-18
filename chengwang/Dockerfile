# syntax=docker/dockerfile:1

FROM node:22-alpine AS web-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.23-alpine AS go-builder
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/chengwang ./cmd/server

FROM alpine:3.21
RUN addgroup -S -g 10001 chengwang \
    && adduser -S -D -H -u 10001 -G chengwang chengwang \
    && mkdir -p /app/data /app/web \
    && chown -R chengwang:chengwang /app
COPY --from=go-builder /out/chengwang /app/chengwang
COPY --from=web-builder /src/web/dist/ /app/web/
USER chengwang
WORKDIR /app
ENV CHENGWANG_ADDR=0.0.0.0:7811 \
    CHENGWANG_DATA_DIR=/app/data \
    CHENGWANG_WEB_DIR=/app/web \
    CHENGWANG_MODE=shadow \
    CHENGWANG_ALLOW_PUBLISH=false
EXPOSE 7811
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:7811/api/v1/health || exit 1
ENTRYPOINT ["/app/chengwang"]
