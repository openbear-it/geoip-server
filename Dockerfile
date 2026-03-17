# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o geoip-server ./cmd/geoip-server/

# ── Production image ──────────────────────────────────────────────────────────
FROM scratch

WORKDIR /app
COPY --from=builder /app/geoip-server .

EXPOSE 8080

ENTRYPOINT ["./geoip-server"]
