package main

import (
	"context"
	"crypto/tls"
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
	"sync"
	"time"
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
	CountryCode string   `json:"country_code,omitempty"`
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
	githubRawURL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/iptoasn-asn/%s"
	defaultDB    = "iptoasn-asn-ipv4.csv"    // Default database file to download and use
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

	// Create database URL
	url := fmt.Sprintf(githubRawURL, dbName)
	
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

// loadIPDatabases manages the loading of IP location databases.
// It downloads the database if needed, handles backup of existing data,
// and updates the metrics after successful loading.
func loadIPDatabases() error {
	log.Printf("[INFO] Loading IP database...")

	if err := downloadDatabase(defaultDB); err != nil {
		log.Printf("[ERROR] Failed to download database: %v", err)
		return err
	}

	// Backup existing database before loading
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

	ipRanges = make([]ipRange, 0) // Reset before loading
	if err := loadIP2Location(defaultDB); err != nil {
		return fmt.Errorf("failed to load database: %v", err)
	}

	if len(ipRanges) == 0 {
		return fmt.Errorf("no IP ranges were loaded from database")
	}

	sortIPRanges()
	log.Printf("[INFO] Total IP ranges loaded and sorted: %d", len(ipRanges))
	
	// Aggiorna le metriche
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
    location := findIPRange(ipInt, ipRanges)

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

// loadIP2Location loads and parses the IP location database from CSV format.
// It handles various data validations including IP format, ASN parsing,
// and proper IPv4 address conversion. Invalid entries are logged and skipped.
func loadIP2Location(path string) error {
    file, err := os.Open(path)
    if err != nil {
        return err
    }
    defer file.Close()

    reader := csv.NewReader(file)
    reader.LazyQuotes = true

    // Skip header if present
    _, err = reader.Read()
    if err != nil {
        return err
    }

    for i := 1; ; i++ {
        record, err := reader.Read()
        if err == io.EOF {
            break
        }
        if err != nil {
            log.Printf("[WARN] Error reading row %d: %v", i, err)
            continue
        }

        if len(record) < 4 {  // format: start_ip, end_ip, asn, country_code
            log.Printf("[WARN] Row %d ignored (only %d columns)", i, len(record))
            continue
        }

        // Convert IPs from dotted decimal format to uint32
        startIP := net.ParseIP(record[0])
        endIP := net.ParseIP(record[1])
        if startIP == nil || endIP == nil {
            log.Printf("[WARN] Row %d has invalid IP format", i)
            continue
        }

        // Convert to IPv4
        startIP = startIP.To4()
        endIP = endIP.To4()
        if startIP == nil || endIP == nil {
            log.Printf("[WARN] Row %d has invalid IPv4 addresses", i)
            continue
        }

        asn, err := strconv.Atoi(record[2])
        if err != nil {
            log.Printf("[WARN] Row %d has invalid ASN: %v", i, err)
            continue
        }

        countryCode := record[3]

        ipRanges = append(ipRanges, ipRange{
            start: binaryIPToInt(startIP),
            end:   binaryIPToInt(endIP),
            location: GeoLocation{
                CountryCode: countryCode,
                Country:    countryCode,
                ASN:       asn,
                Sources:   []string{"iptoasn"},
            },
        })
    }

    log.Printf("[INFO] Loaded %d IP ranges from IPtoASN database", len(ipRanges))
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

// Loads the IP2Location CSV database into memory

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
