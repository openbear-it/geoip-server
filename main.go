package main

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// Global variables for managing IP ranges, database state, and request tracking
var (
	ipRanges       []ipRange        // Stores IP ranges with their associated location data
	ipRangesMutex  sync.RWMutex     // Protects concurrent access to ipRanges
	dbLoadedMutex  sync.RWMutex     // Protects concurrent access to dbLoaded flag
	dbLoaded       bool             // Indicates whether the database is loaded and ready
	requestCounter = make(map[string]int) // Tracks requests per source
	requestMutex   sync.RWMutex     // Protects concurrent access to requestCounter
	startTime      = time.Now()     // Server start time for uptime tracking
	clientStats    = make(map[string]*clientData) // Stores client request statistics for rate limiting
	statsMu        sync.RWMutex     // Protects concurrent access to clientStats
	// Postgres connection (optional)
	pgDB  *sql.DB
	usePG bool
)

// Cache implementation for reducing database lookups
type cacheEntry struct {
	data       []byte
	expiration time.Time
}

var (
	cache    = make(map[string]cacheEntry)
	cacheMu  sync.RWMutex
)

// Metrics structure
type metrics struct {
	DatabaseSize    int       `json:"database_size"`
	CacheHits      int64     `json:"cache_hits"`
	CacheMisses    int64     `json:"cache_misses"`
	TotalRequests  int64     `json:"total_requests"`
	AverageLatency float64   `json:"average_latency_ms"`
	LastRefresh    time.Time `json:"last_refresh"`
}

var (
	metricsData metrics
	metricsMu   sync.RWMutex
)

// Cache functions
func getCachedResponse(key string) ([]byte, bool) {
	cacheMu.RLock()
	entry, exists := cache[key]
	cacheMu.RUnlock()
	
	if !exists || time.Now().After(entry.expiration) {
		return nil, false
	}
	return entry.data, true
}

func setCachedResponse(key string, data []byte, duration time.Duration) {
	cacheMu.Lock()
	cache[key] = cacheEntry{
		data:       data,
		expiration: time.Now().Add(duration),
	}
	cacheMu.Unlock()
}

// Metrics functions
func updateMetrics(updater func(*metrics)) {
	metricsMu.Lock()
	updater(&metricsData)
	metricsMu.Unlock()
}

// Client data for rate limiting
type clientData struct {
	mu         sync.Mutex
	timestamps []time.Time
}

type GeoLocation struct {
	IP          string   `json:"ip"`
	Country     string   `json:"country"`
	City        string   `json:"city,omitempty"`
	Region      string   `json:"region,omitempty"`
	Latitude    float64  `json:"latitude,omitempty"`
	Longitude   float64  `json:"longitude,omitempty"`
	ASN         int      `json:"asn,omitempty"`
	ASNOrg      string   `json:"asn_org,omitempty"`
	TimeZone    string   `json:"timezone,omitempty"`
	Sources     []string `json:"sources,omitempty"`
}

type ipRange struct {
	start    uint32
	end      uint32
	location GeoLocation
}

const (
	serverPort     = "0.0.0.0:8080"    // Server listening address and port
	requestLimit   = 10                 // Maximum requests per client in the time window
	windowDuration = time.Minute        // Time window for rate limiting

	// IP location database configuration
	githubBaseURL = "https://raw.githubusercontent.com/sapics/ip-location-db/main"
	cityDB        = "dbip-city/dbip-city-ipv4.csv.gz" // Single gzipped city DB to use
)

// findIPRange performs a binary search to efficiently locate the IP range containing the given IP
// Returns a pointer to the matching ipRange or nil if not found
func findIPRange(ipInt uint32, ranges []ipRange) *ipRange {
	ipRangesMutex.RLock()
	defer ipRangesMutex.RUnlock()

	left := 0
	right := len(ranges) - 1

	for left <= right {
		mid := (left + right) / 2
		if ipInt >= ranges[mid].start && ipInt <= ranges[mid].end {
			return &ranges[mid]
		}
		if ipInt < ranges[mid].start {
			right = mid - 1
		} else {
			left = mid + 1
		}
	}
	return nil
}

// downloadDatabase scarica il database CSV se non esiste localmente
// downloadDatabase downloads the CSV database if it doesn't exist locally.
// It handles file creation, directory setup, and data download from the remote source.
func downloadDatabase(dbName string) error {
    // Check if the file already exists
	if _, err := os.Stat(dbName); err == nil {
		log.Printf("[INFO] Database %s already exists", dbName)
		return nil
	}

	log.Printf("[INFO] Downloading database %s...", dbName)

	// Create database URL for the city DB
	url := fmt.Sprintf("%s/%s", githubBaseURL, dbName)
	
	// Create a custom HTTP client that skips TLS verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	
	// Download the file
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download database: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download database, status: %s", resp.Status)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(dbName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Create local file
	out, err := os.Create(dbName)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer out.Close()

	// Copy content
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save database: %v", err)
	}

	log.Printf("[INFO] Database %s downloaded successfully", dbName)
	return nil
}

// loadIPDatabases manages loading the single gzipped city database.
// It downloads the database if needed, handles backup of existing data,
// loads the city DB and updates metrics.
func loadIPDatabases() error {
	log.Printf("[INFO] Loading IP database (city DB)...")

	// If PG_DSN is set, import into Postgres and use DB queries
	pgdsn := os.Getenv("PG_DSN")
	if pgdsn != "" {
		log.Printf("[INFO] PG_DSN detected, initializing Postgres import")
		if err := initPostgres(pgdsn); err != nil {
			log.Printf("[ERROR] Failed to initialize Postgres: %v", err)
			return err
		}

		// Ensure CSV is present locally
		if err := downloadDatabase(cityDB); err != nil {
			log.Printf("[ERROR] Failed to download city database: %v", err)
			return err
		}

		log.Printf("[INFO] Importing CSV into Postgres...")
		if err := importCSVToPostgres(cityDB); err != nil {
			log.Printf("[ERROR] Failed to import CSV to Postgres: %v", err)
			return err
		}

		usePG = true
		setDBLoaded(true)
		updateMetrics(func(m *metrics) {
			m.DatabaseSize = 0
			m.LastRefresh = time.Now()
		})
		log.Printf("[INFO] Postgres import completed; using DB for lookups")
		return nil
	}

	// Fallback: load into memory
	if err := downloadDatabase(cityDB); err != nil {
		log.Printf("[ERROR] Failed to download city database: %v", err)
		return err
	}

	// Backup existing ranges
	if len(ipRanges) > 0 {
		oldRanges := make([]ipRange, len(ipRanges))
		copy(oldRanges, ipRanges)
		defer func() {
			if len(ipRanges) == 0 {
				ipRanges = oldRanges
				log.Printf("[INFO] Restored previous database after failed load")
			}
		}()
	}

	ipRanges = make([]ipRange, 0)
	if err := loadCityDB(cityDB); err != nil {
		return fmt.Errorf("failed to load city DB: %v", err)
	}

	if len(ipRanges) == 0 {
		return fmt.Errorf("no IP ranges were loaded from city DB")
	}

	sortIPRanges()
	log.Printf("[INFO] Total IP ranges loaded and sorted: %d", len(ipRanges))

	updateMetrics(func(m *metrics) {
		m.DatabaseSize = len(ipRanges)
		m.LastRefresh = time.Now()
	})

	return nil
}

// handlerJSON processes JSON requests for IP geolocation.
// It implements caching, input validation, and error handling.
// Returns IP location data in JSON format with appropriate HTTP status codes.
func handlerJSON(w http.ResponseWriter, r *http.Request) {
    start := time.Now()
    ipStr := getIP(r)
    
    // Check cache
    if cached, hit := getCachedResponse(ipStr); hit {
        w.Header().Set("Content-Type", "application/json")
        w.Write(cached)
        updateMetrics(func(m *metrics) {
            m.CacheHits++
        })
        logRequest(r, http.StatusOK, time.Since(start), nil)
        return
    }

    ip := net.ParseIP(ipStr)
    if ip == nil {
        err := fmt.Errorf("invalid IP address")
        logRequest(r, http.StatusBadRequest, time.Since(start), err)
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Verify it's a valid IPv4 address
    ip4 := ip.To4()
    if ip4 == nil {
        err := fmt.Errorf("IPv6 not supported")
        logRequest(r, http.StatusBadRequest, time.Since(start), err)
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    ipInt := binaryIPToInt(ip4)
		var location *ipRange
		if usePG {
			// query Postgres
			pgLoc, err := queryPGForIP(ipInt)
			if err != nil {
				logRequest(r, http.StatusInternalServerError, time.Since(start), err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			if pgLoc != nil {
					// sanitize coordinates: if one of lat/lon is zero-value (missing), drop both
					sanitizeCoords(&pgLoc.Latitude, &pgLoc.Longitude)
				// build response from pgLoc
				respBytes, err := json.Marshal(struct {
					IP       string   `json:"ip"`
					Country  string   `json:"country"`
					City     string   `json:"city,omitempty"`
					Latitude float64  `json:"latitude,omitempty"`
					Longitude float64 `json:"longitude,omitempty"`
					Sources  []string `json:"sources,omitempty"`
				}{
					IP: ipStr,
					Country: pgLoc.Country,
					City: pgLoc.City,
					Latitude: pgLoc.Latitude,
					Longitude: pgLoc.Longitude,
					Sources: pgLoc.Sources,
				})
				if err != nil {
					logRequest(r, http.StatusInternalServerError, time.Since(start), err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(respBytes)
				setCachedResponse(ipStr, respBytes, 1*time.Hour)
				updateMetrics(func(m *metrics) {
					m.CacheMisses++
					m.TotalRequests++
					m.AverageLatency = (m.AverageLatency*float64(m.TotalRequests-1) + float64(time.Since(start).Milliseconds())) / float64(m.TotalRequests)
				})
				logRequest(r, http.StatusOK, time.Since(start), nil)
				return
			}
			// fallthrough to in-memory if not found in DB
		}
		location = findIPRange(ipInt, ipRanges)

    if location == nil {
        // If we don't find a range, still return the IP
        response := GeoLocation{
            IP:      ipStr,
            Sources: []string{"unknown"},
        }
        
        jsonResponse, err := json.Marshal(response)
        if err != nil {
            logRequest(r, http.StatusInternalServerError, time.Since(start), err)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        w.Write(jsonResponse)
        logRequest(r, http.StatusOK, time.Since(start), nil)
        return
    }

	// Ensure we have the correct IP in the response
	location.location.IP = ipStr

	// sanitize coordinates for in-memory responses as well
	sanitizeCoords(&location.location.Latitude, &location.location.Longitude)
    
    response, err := json.Marshal(location.location)
    if err != nil {
        logRequest(r, http.StatusInternalServerError, time.Since(start), err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    // Cache the response
    setCachedResponse(ipStr, response, 1*time.Hour)
    
    w.Header().Set("Content-Type", "application/json")
    w.Write(response)
    
    updateMetrics(func(m *metrics) {
        m.CacheMisses++
        m.TotalRequests++
        m.AverageLatency = (m.AverageLatency*float64(m.TotalRequests-1) + float64(time.Since(start).Milliseconds())) / float64(m.TotalRequests)
    })
    
    logRequest(r, http.StatusOK, time.Since(start), nil)
}

// binaryIPToInt safely converts an IP address to uint32
func binaryIPToInt(ip net.IP) uint32 {
    if ip == nil || len(ip) < 4 {
        return 0
    }
    return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// sanitizeCoords clears both latitude and longitude when one of them is absent
// or clearly invalid (zero value). This ensures responses never include a lone
// latitude or longitude value.
func sanitizeCoords(lat *float64, lon *float64) {
	if lat == nil || lon == nil {
		return
	}
	// consider zero as missing; also guard against NaN though ParseFloat won't produce NaN here
	if *lat == 0 || *lon == 0 {
		*lat = 0
		*lon = 0
	}
}

// loadIP2Location loads and parses the IP location database from CSV format.
// It handles various data validations including IP format, ASN parsing,
// and proper IPv4 address conversion. Invalid entries are logged and skipped.
// loadCityDB reads a gzipped CSV city database and populates ipRanges.
// Expected CSV columns (dbip-city common layout):
// ip_from,ip_to,country_code,country_name,region,city,latitude,longitude
func loadCityDB(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var rdr io.Reader = f
	if filepath.Ext(path) == ".gz" {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %v", err)
		}
		defer gz.Close()
		rdr = gz
	}

	csvr := csv.NewReader(rdr)
	csvr.LazyQuotes = true

	// Read header
	header, err := csvr.Read()
	if err != nil {
		return fmt.Errorf("failed to read header: %v", err)
	}

	idx := make(map[string]int)
	for i, h := range header {
		idx[h] = i
	}

	get := func(rec []string, name string, fallback int) string {
		if pos, ok := idx[name]; ok && pos < len(rec) {
			return rec[pos]
		}
		if fallback >= 0 && fallback < len(rec) {
			return rec[fallback]
		}
		return ""
	}

	for i := 1; ; i++ {
		rec, err := csvr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("[WARN] Error reading city DB row %d: %v", i, err)
			continue
		}

		startStr := get(rec, "ip_from", 0)
		endStr := get(rec, "ip_to", 1)

		var startIP, endIP net.IP
		if startStr != "" && !strings.Contains(startStr, ".") {
			v, err := strconv.ParseUint(startStr, 10, 64)
			if err == nil {
				b := []byte{byte((v >> 24) & 0xFF), byte((v >> 16) & 0xFF), byte((v >> 8) & 0xFF), byte(v & 0xFF)}
				startIP = net.IPv4(b[0], b[1], b[2], b[3])
			}
		} else if startStr != "" {
			startIP = net.ParseIP(startStr)
		}

		if endStr != "" && !strings.Contains(endStr, ".") {
			v, err := strconv.ParseUint(endStr, 10, 64)
			if err == nil {
				b := []byte{byte((v >> 24) & 0xFF), byte((v >> 16) & 0xFF), byte((v >> 8) & 0xFF), byte(v & 0xFF)}
				endIP = net.IPv4(b[0], b[1], b[2], b[3])
			}
		} else if endStr != "" {
			endIP = net.ParseIP(endStr)
		}

		if startIP == nil || endIP == nil {
			log.Printf("[WARN] Row %d: invalid IPs (%s - %s)", i, startStr, endStr)
			continue
		}

		s4 := startIP.To4()
		e4 := endIP.To4()
		if s4 == nil || e4 == nil {
			log.Printf("[WARN] Row %d: non-IPv4 addresses", i)
			continue
		}

		country := get(rec, "country_code", 2)
		city := get(rec, "city", 5)
		latStr := get(rec, "latitude", 6)
		lonStr := get(rec, "longitude", 7)

		lat, _ := strconv.ParseFloat(latStr, 64)
		lon, _ := strconv.ParseFloat(lonStr, 64)

		ipRanges = append(ipRanges, ipRange{
			start: binaryIPToInt(s4),
			end:   binaryIPToInt(e4),
			location: GeoLocation{
				Country:     country,
				City:        city,
				Latitude:    lat,
				Longitude:   lon,
				Sources:     []string{"dbip-city"},
			},
		})
	}

	log.Printf("[INFO] Loaded %d IP ranges from city DB", len(ipRanges))
	return nil
}

// Sets the dbLoaded flag in a thread-safe way
func setDBLoaded(loaded bool) {
	dbLoadedMutex.Lock()
	defer dbLoadedMutex.Unlock()
	dbLoaded = loaded
}

// Gets the dbLoaded flag in a thread-safe way
func isDBLoaded() bool {
	dbLoadedMutex.RLock()
	defer dbLoadedMutex.RUnlock()
	return dbLoaded
}

// initPostgres opens a connection to Postgres using the provided DSN
func initPostgres(dsn string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	// simple ping to verify
	if err := db.Ping(); err != nil {
		db.Close()
		return err
	}
	pgDB = db
	return nil
}

// importCSVToPostgres imports the gzipped CSV into a temp table and swaps it in atomically.
func importCSVToPostgres(path string) error {
	if pgDB == nil {
		return fmt.Errorf("pgDB is nil")
	}

	tx, err := pgDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Create temp table
	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS geoip_city_new (
		ip_from bigint NOT NULL,
		ip_to bigint NOT NULL,
		country text,
		city text,
		region text,
		latitude double precision,
		longitude double precision,
		source text
	)`)
	if err != nil {
		return err
	}

	// Truncate new table
	if _, err := tx.Exec(`TRUNCATE geoip_city_new`); err != nil {
		return err
	}

	// Use COPY via pq
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var rdr io.Reader = f
	if filepath.Ext(path) == ".gz" {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		rdr = gz
	}

	// Stream CSV rows and insert in the same transaction so created table is visible
	reader := csv.NewReader(rdr)
	reader.LazyQuotes = true
	// Read header
	if _, err := reader.Read(); err != nil {
		return err
	}

	// Prepare insert statement on the transaction so it runs in the same session
	stmt, err := tx.Prepare(`INSERT INTO geoip_city_new (ip_from, ip_to, country, city, region, latitude, longitude, source) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	batch := 0
	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("[WARN] csv read err: %v", err)
			continue
		}

		// parse ip_from/ip_to
		ipFromStr := rec[0]
		ipToStr := rec[1]
		var ipFrom, ipTo int64
		if strings.Contains(ipFromStr, ".") {
			p := net.ParseIP(ipFromStr).To4()
			if p == nil { continue }
			ipFrom = int64(binaryIPToInt(p))
		} else {
			v, _ := strconv.ParseInt(ipFromStr, 10, 64)
			ipFrom = v
		}
		if strings.Contains(ipToStr, ".") {
			p := net.ParseIP(ipToStr).To4()
			if p == nil { continue }
			ipTo = int64(binaryIPToInt(p))
		} else {
			v, _ := strconv.ParseInt(ipToStr, 10, 64)
			ipTo = v
		}

		country := ""
		city := ""
		region := ""
		lat := 0.0
		lon := 0.0
		source := "dbip-city"
		if len(rec) > 2 { country = rec[2] }
		if len(rec) > 5 { city = rec[5] }
		if len(rec) > 4 { region = rec[4] }
		if len(rec) > 6 { lat, _ = strconv.ParseFloat(rec[6], 64) }
		if len(rec) > 7 { lon, _ = strconv.ParseFloat(rec[7], 64) }

		if _, err := stmt.Exec(ipFrom, ipTo, country, city, region, lat, lon, source); err != nil {
			log.Printf("[WARN] insert err: %v", err)
			continue
		}
		batch++
		if batch%10000 == 0 {
			log.Printf("[INFO] imported %d rows...", batch)
		}
	}

	// Commit transaction to make new table ready
	if err := tx.Commit(); err != nil {
		return err
	}

	// Swap tables
	swapTx, err := pgDB.Begin()
	if err != nil {
		return err
	}
	if _, err := swapTx.Exec(`ALTER TABLE IF EXISTS geoip_city RENAME TO geoip_city_old`); err != nil {
		swapTx.Rollback()
		return err
	}
	if _, err := swapTx.Exec(`ALTER TABLE geoip_city_new RENAME TO geoip_city`); err != nil {
		swapTx.Rollback()
		return err
	}
	if err := swapTx.Commit(); err != nil {
		return err
	}

	// Drop old
	if _, err := pgDB.Exec(`DROP TABLE IF EXISTS geoip_city_old`); err != nil {
		log.Printf("[WARN] failed to drop old table: %v", err)
	}

	return nil
}

// queryPGForIP looks up the IP in Postgres and returns a GeoLocation if found
func queryPGForIP(ipInt uint32) (*GeoLocation, error) {
	if pgDB == nil { return nil, fmt.Errorf("pg not initialized") }
	var loc GeoLocation
	row := pgDB.QueryRow(`SELECT country, city, latitude, longitude, source FROM geoip_city WHERE ip_from <= $1 AND ip_to >= $1 LIMIT 1`, int64(ipInt))
	var source string
	if err := row.Scan(&loc.Country, &loc.City, &loc.Latitude, &loc.Longitude, &source); err != nil {
		if err == sql.ErrNoRows { return nil, nil }
		return nil, err
	}
	loc.Sources = []string{source}
	return &loc, nil
}

// (removed old ASN-country loader - using single dbip-city gzip CSV instead)

// rateLimitMiddleware implements rate limiting per IP address.
// It enforces request limits within a sliding time window and
// adds security headers to all responses. Excess requests receive 429 Too Many Requests.
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getIP(r)
		if ip == "" {
			log.Printf("[ERROR] Invalid IP address in request - UA: %q", r.UserAgent())
			http.Error(w, "Invalid IP address", http.StatusBadRequest)
			logRequest(r, http.StatusBadRequest, 0, fmt.Errorf("invalid ip"))
			return
		}

		statsMu.RLock()
		data, exists := clientStats[ip]
		statsMu.RUnlock()
		if !exists {
			data = &clientData{}
			statsMu.Lock()
			clientStats[ip] = data
			statsMu.Unlock()
		}

		data.mu.Lock()
		now := time.Now()
		valid := data.timestamps[:0]
		for _, t := range data.timestamps {
			if now.Sub(t) < windowDuration {
				valid = append(valid, t)
			}
		}
		data.timestamps = valid

		if len(data.timestamps) >= requestLimit {
			data.mu.Unlock()
			log.Printf("[WARN] Rate limit exceeded for IP %s - UA: %q", ip, r.UserAgent())
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			logRequest(r, http.StatusTooManyRequests, 0, fmt.Errorf("rate limit exceeded"))
			return
		}

		data.timestamps = append(data.timestamps, now)
		data.mu.Unlock()

		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		next.ServeHTTP(w, r)
	})
}

// getIP extracts the client's IP address from the request.
// It handles X-Forwarded-For headers for proxy support and falls back
// to RemoteAddr if no proxy headers are present.
func getIP(r *http.Request) string {
	// Check X-Forwarded-For header for proxies
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := net.ParseIP(xff)
		if ips != nil {
			return ips.String()
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return ip
}

type logEntry struct {
	Timestamp   time.Time   `json:"timestamp"`
	Level       string      `json:"level"`
	Message     string      `json:"message"`
	Method      string      `json:"method,omitempty"`
	Path        string      `json:"path,omitempty"`
	IP          string      `json:"ip,omitempty"`
	UserAgent   string      `json:"user_agent,omitempty"`
	StatusCode  int         `json:"status_code,omitempty"`
	Latency     float64     `json:"latency,omitempty"`
	Error       string      `json:"error,omitempty"`
}

func logRequest(r *http.Request, status int, latency time.Duration, err error) {
	entry := &logEntry{
		Timestamp:  time.Now(),
		Level:      "INFO",
		Method:     r.Method,
		Path:       r.URL.Path,
		IP:         getIP(r),
		UserAgent:  r.UserAgent(),
		StatusCode: status,
		Latency:    float64(latency.Microseconds()) / 1000,
	}

	if err != nil {
		entry.Level = "ERROR"
		entry.Error = err.Error()
	}

	json.NewEncoder(os.Stdout).Encode(entry)
}

// Plain text handler for /api/myip/plain
func handlerPlain(w http.ResponseWriter, r *http.Request) {
	ipStr := getIP(r)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Printf("[ERROR] Invalid IP address in handlerPlain - UA: %q", r.UserAgent())
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		logRequest(r, http.StatusBadRequest, 0, fmt.Errorf("invalid ip"))
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(ipStr))
	logRequest(r, http.StatusOK, 0, nil)
}

// healthHandler implements the health check endpoint.
// Returns 'ok' if the database is loaded, 'degraded' otherwise.
// Used for monitoring and load balancer health checks.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	if !isDBLoaded() {
		status = "degraded"
	}
	resp := map[string]string{
		"status": status,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	logRequest(r, http.StatusOK, 0, nil)
}

func getMetrics() map[string]interface{} {
	requestMutex.RLock()
	defer requestMutex.RUnlock()

	return map[string]interface{}{
		"total_ranges":     len(ipRanges),
		"request_counter":  requestCounter,
		"database_loaded":  isDBLoaded(),
		"uptime":          time.Since(startTime).String(),
	}
}

// metricsHandler serves runtime metrics about the server.
// Provides information about database size, request counts,
// server uptime, and database load status in JSON format.
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := getMetrics()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// Sort IP ranges after loading all databases
func sortIPRanges() {
    sort.Slice(ipRanges, func(i, j int) bool {
        return ipRanges[i].start < ipRanges[j].start
    })
}

func setupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/api/myip", http.StatusTemporaryRedirect)
			return
		}
		http.NotFound(w, r)
	})

	mux.Handle("/api/myip", rateLimitMiddleware(http.HandlerFunc(handlerJSON)))
	mux.Handle("/api/myip/plain", rateLimitMiddleware(http.HandlerFunc(handlerPlain)))
	mux.Handle("/health", http.HandlerFunc(healthHandler))
	mux.Handle("/metrics", http.HandlerFunc(metricsHandler))
}

func startDatabaseRefresher(ctx context.Context, interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            log.Printf("[INFO] Starting scheduled database refresh")
            if err := loadIPDatabases(); err != nil {
                log.Printf("[ERROR] Failed to refresh database: %v", err)
            }
        }
    }
}

// main initializes and starts the IP geolocation server.
// It handles database loading, periodic refresh setup,
// route configuration, and graceful server startup.
func main() {
    log.Printf("[INFO] Starting server on %s", serverPort)

    // Load database at startup
    if err := loadIPDatabases(); err != nil {
        log.Fatalf("[FATAL] Failed to load initial database: %v", err)
    }
    setDBLoaded(true)

    // Start periodic database refresh
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    go startDatabaseRefresher(ctx, 24*time.Hour)

    // Setup routes
    mux := http.NewServeMux()
    setupRoutes(mux)

    // Start the server
    server := &http.Server{
        Addr:         serverPort,
        Handler:      mux,
        ReadTimeout:  5 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    log.Printf("[INFO] Server started successfully")
    if err := server.ListenAndServe(); err != http.ErrServerClosed {
        log.Fatalf("[FATAL] Server failed to start: %v", err)
    }
}
