# ---------- build stage ----------
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY web/ web/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /forward-proxy .

# ---------- runtime stage ----------
FROM alpine:3.21
RUN apk add --no-cache ca-certificates \
    && adduser -D -H -s /bin/sh proxy \
    && mkdir -p /data && chown proxy:proxy /data
ENV DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 3128 8080
COPY --from=build /forward-proxy /usr/local/bin/forward-proxy
USER proxy
# Healthcheck hits the proxy port (never TLS), so it works regardless of
# whether the admin listener is wrapped in TLS via TLS_CERT_FILE/TLS_KEY_FILE.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3128/healthz >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/usr/local/bin/forward-proxy"]
