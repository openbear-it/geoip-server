# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod if it exists, otherwise skip go.sum
COPY go.mod ./
# Only run go mod download if go.mod is present
RUN [ -f go.mod ] && go mod download || true

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o geoip-server main.go

# Production image
FROM scratch

WORKDIR /app
COPY --from=builder /app/geoip-server .
COPY --from=builder /app/ip2location.csv .

EXPOSE 8080

ENTRYPOINT ["./geoip-server"]
