# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o geoip-server main.go

# Production image
FROM scratch

WORKDIR /app
COPY --from=builder /app/geoip-server .
COPY --from=builder /app/ip2location.csv .

EXPOSE 8080

ENTRYPOINT ["./geoip-server"]
