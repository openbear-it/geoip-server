# GeoIP Server

A fast, lightweight IPv4 geolocation HTTP service written in Go.  
Supports in-memory lookups and PostgreSQL for production-scale deployments.

## Project Layout

```
.
├── cmd/
│   └── geoip-server/
│       ├── main.go          # Application entry point and all handlers
│       └── main_test.go     # Unit and integration tests
├── scripts/
│   └── inspect_csv.sh       # Helper to inspect CSV dataset schemas
├── .github/
│   └── workflows/
│       ├── ci.yml           # Go test + vet on every push/PR
│       ├── sonarqube.yml    # SonarQube static analysis (main branch)
│       └── docker-image.yml # Build & push multi-arch Docker image
├── Dockerfile               # Multi-stage production build
├── .dockerignore
├── .gitignore
├── go.mod
└── go.sum
```

## Features

- IPv4 geolocation (city, region, country, latitude/longitude)
- ASN lookup and enrichment
- Dual storage: **PostgreSQL** (production) or **in-memory** (zero-dep)
- Response caching with TTL and LRU eviction
- Per-IP rate limiting (configurable) with automatic IP blocking
- Bulk lookup: up to 100 IPs in a single POST request
- CORS headers + `OPTIONS` preflight support
- `Cache-Control` headers on JSON responses
- Standard security headers (`X-Content-Type-Options`, `X-Frame-Options`, …)
- Safe `X-Forwarded-For` handling via configurable trusted proxies
- Graceful shutdown on `SIGTERM` / `SIGINT`
- Interactive map view via Leaflet.js (`/maps`)
- Health check endpoint (`/health`)
- Metrics in JSON (`/metrics`) and **Prometheus** (`/metrics/prometheus`)
- Structured JSON access logs
- Multi-arch Docker image (`linux/amd64`, `linux/arm64`)
- Checksum-based import deduplication (skip re-import of unchanged datasets)

## Quick Start

### Local build

```sh
go build -o geoip-server ./cmd/geoip-server/
./geoip-server
```

### Docker

```sh
docker build -t geoip-server .
docker run -p 8080:8080 geoip-server
```

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/myip` | Geolocation of the calling IP (JSON) |
| `GET` | `/api/myip/plain` | Calling IP address as plain text |
| `POST` | `/api/lookup` | Bulk lookup – up to 100 IPs |
| `GET` | `/maps?ip=<ip>` | Interactive Leaflet map for an IP |
| `GET` | `/health` | `{"status":"ok"}` / `{"status":"degraded"}` |
| `GET` | `/metrics` | Runtime metrics (JSON) |
| `GET` | `/metrics/prometheus` | Runtime metrics (Prometheus text format) |

### `GET /api/myip`

```json
{
  "ip": "8.8.8.8",
  "country": "US",
  "region": "California",
  "city": "Mountain View",
  "latitude": 37.386,
  "longitude": -122.0838,
  "asn": 15169,
  "asn_org": "GOOGLE",
  "sources": ["dbip-city", "asn-db"]
}
```

### `POST /api/lookup`

```jsonc
// Request
{ "ips": ["8.8.8.8", "1.1.1.1"] }

// Response – array in same order
[
  { "ip": "8.8.8.8", "country": "US", ... },
  { "ip": "1.1.1.1", "country": "AU", ... }
]
```

## Configuration

All settings are controlled via environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | TCP port to listen on |
| `RATE_LIMIT` | `10` | Max requests per minute per IP |
| `TRUSTED_PROXIES` | _(none)_ | Comma-separated CIDRs/IPs whose `X-Forwarded-For` is trusted |
| `INSECURE_TLS` | `true` | Set to `false` to enable TLS verification for dataset downloads |
| `PG_DSN` | _(none)_ | PostgreSQL DSN. When set, datasets are imported into Postgres |
| `CITY` | `dbip-city/dbip-city-ipv4.csv.gz` | Path to city dataset |
| `COUNTRY` | _(none)_ | Path to country-only dataset (optional fallback) |
| `ASN` | `asn/asn-ipv4.csv` | Path to ASN dataset |
| `IMPORT_BATCH_SIZE` | `10000` | Rows per transaction during Postgres import |

### Example: run with PostgreSQL

```sh
docker run -p 8080:8080 \
  -e PG_DSN="postgres://user:pass@db:5432/geoip?sslmode=disable" \
  -e TRUSTED_PROXIES="10.0.0.0/8,172.16.0.0/12" \
  -e RATE_LIMIT="60" \
  ghcr.io/<your-org>/geoip-server:latest
```

## Development

```sh
# Run tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Vet
go vet ./...
```

## License

MIT License
