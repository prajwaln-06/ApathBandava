# Build stage: cgo needed for mattn/go-sqlite3 (whatsmeow session store)
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/wa-bridge .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* && useradd -r -u 10002 bridge \
    && mkdir -p /store /media && chown bridge /store /media
COPY --from=build /out/wa-bridge /usr/local/bin/wa-bridge
USER bridge
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD curl -fsS http://127.0.0.1:8080/api/health || exit 1
ENTRYPOINT ["/usr/local/bin/wa-bridge"]
