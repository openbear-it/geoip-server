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

### Build and Run Locally

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

The server automatically detects the client IP (supports `X-Forwarded-For`).

## Configuration

- The server listens on port `8080` by default.
- The IP database file must be named `ip2location.csv` and placed in the working directory.

## Docker

The provided `Dockerfile` builds a minimal production image.  
You can deploy the container anywhere Docker is supported.

## License

MIT License