# GeoIP Server

GeoIP Server is a lightweight HTTP service written in Go that provides country lookup for IPv4 addresses using a local CSV database (such as IP2Location).  
It features per-IP rate limiting and is ready for production deployment via Docker.

## Features

- Fast IPv4 to country lookup using a CSV database
- Per-client rate limiting (default: 10 requests per minute)
- Secure HTTP headers
- Ready-to-use Docker container
- Simple JSON API

## Usage

### Build and run locally

```sh
go build -o geoip-server main.go
./geoip-server
```

### Run with Docker

```sh
docker build -t geoip-server .
docker run -p 8080:8080 geoip-server
```

### API

- **Endpoint:** `GET /`
- **Response:**
  ```json
  {
    "ip": "8.8.8.8",
    "country": "US"
  }
  ```

The server detects the client IP (supports `X-Forwarded-For`).

## Configuration & Notes

- Key environment variables:
  - `PG_DSN`: Postgres DSN. If set, datasets are imported into Postgres and the service uses DB lookups (saves RAM).
  - `CITY`, `COUNTRY`, `ASN`: paths or URLs to dataset files to load.
  - `IMPORT_BATCH_SIZE`: number of rows per commit during imports (default `10000`).
- Import behaviour:
  - When `PG_DSN` is set the server imports datasets into Postgres. ASN is imported before the city database to ensure ASN enrichment is available during lookups.
  - The ASN importer is resilient to transient insert errors: it commits per-batch and restarts the insert transaction on errors to avoid aborted-transaction failures.
  - The service marks itself healthy (`/health`) before performing heavy imports so orchestrators know the process is alive.

## Docker

The provided `Dockerfile` builds a minimal production image. You can deploy the container anywhere Docker is supported.

## License

MIT License