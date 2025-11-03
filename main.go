package main

import (
	"context"
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

// Global variables
var (
	ipRanges       []ipRange
	ipRangesMutex  sync.RWMutex
	dbLoadedMutex  sync.RWMutex
	dbLoaded       bool
	requestCounter = make(map[string]int)
	requestMutex   sync.RWMutex
	startTime      = time.Now()
	clientStats    = make(map[string]*clientData)
	statsMu        sync.RWMutex
)

// Cache implementation
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
	serverPort     = "0.0.0.0:8080"
	requestLimit   = 10
	windowDuration = time.Minute

	// Solo il database iptoasn
	githubRawURL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/iptoasn-asn/%s"
	defaultDB    = "iptoasn-asn-ipv4.csv"    // Database predefinito da scaricare
)

// Binary Search implementation per migliorare le performance
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
// downloadDatabase scarica il database CSV se non esiste localmente
func downloadDatabase(dbName string) error {
	// Verifica se il file esiste già
	if _, err := os.Stat(dbName); err == nil {
		log.Printf("[INFO] Database %s already exists", dbName)
		return nil
	}

	log.Printf("[INFO] Downloading database %s...", dbName)

	// Crea l'URL del database
	url := fmt.Sprintf(githubRawURL, dbName)

	// Scarica il file
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download database: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download database, status: %s", resp.Status)
	}

	// Crea la directory se non esiste
	dir := filepath.Dir(dbName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Crea il file locale
	out, err := os.Create(dbName)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer out.Close()

	// Copia il contenuto
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save database: %v", err)
	}

	log.Printf("[INFO] Database %s downloaded successfully", dbName)
	return nil
}

// Semplifichiamo loadIPDatabases per usare solo il database iptoasn
func loadIPDatabases() error {
	log.Printf("[INFO] Loading IP database...")

	if err := downloadDatabase(defaultDB); err != nil {
		log.Printf("[ERROR] Failed to download database: %v", err)
		return err
	}

	// Backup del database esistente prima del caricamento
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

	ipRanges = make([]ipRange, 0) // Reset prima del caricamento
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

// Versione migliorata del handler JSON
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

    // Verifica che sia un IPv4 valido
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
        // Se non troviamo il range, restituiamo comunque l'IP
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

    // Assicuriamoci di avere l'IP corretto nella risposta
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

// Funzione più sicura per convertire IP in uint32
func binaryIPToInt(ip net.IP) uint32 {
    if ip == nil || len(ip) < 4 {
        return 0
    }
    return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// Loads the IP2Location CSV database into memory
func loadIP2Location(path string) error {
    file, err := os.Open(path)
    if err != nil {
        return err
    }
    defer file.Close()

    reader := csv.NewReader(file)
    reader.LazyQuotes = true

    // Salta l'header se presente
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

        if len(record) < 4 {  // formato: start_ip, end_ip, asn, country_code
            log.Printf("[WARN] Row %d ignored (only %d columns)", i, len(record))
            continue
        }

        // Converte gli IP da formato dotted decimal a uint32
        startIP := net.ParseIP(record[0])
        endIP := net.ParseIP(record[1])
        if startIP == nil || endIP == nil {
            log.Printf("[WARN] Row %d has invalid IP format", i)
            continue
        }

        // Converti in IPv4
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

// Loads the DB-IP CSV database into memory
func loadDBIP(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.LazyQuotes = true

	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	for i, record := range records {
		if len(record) < 3 {
			continue
		}

		startIP := net.ParseIP(record[0])
		endIP := net.ParseIP(record[1])
		if startIP == nil || endIP == nil {
			log.Printf("[WARN] Invalid IP range at row %d", i)
			continue
		}

		ipRanges = append(ipRanges, ipRange{
			start: binaryIPToInt(startIP.To4()),
			end:   binaryIPToInt(endIP.To4()),
			location: GeoLocation{
				Country:     record[2],
				CountryCode: record[2],
				Sources:     []string{"dbip"},
			},
		})
	}

	log.Printf("[INFO] Loaded %d ranges from DB-IP database", len(records))
	return nil
}

// Loads the Geofeed CSV database into memory
func loadGeoFeed(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.LazyQuotes = true

	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	for i, record := range records {
		if len(record) < 3 {
			continue
		}

		_, network, err := net.ParseCIDR(record[0])
		if err != nil {
			log.Printf("[WARN] Invalid CIDR at row %d: %v", i, err)
			continue
		}

		// Convert CIDR to start/end IP range
		startIP := network.IP
		mask := network.Mask
		endIP := make(net.IP, len(startIP))
		copy(endIP, startIP)
		for i := range endIP {
			endIP[i] |= ^mask[i]
		}

		ipRanges = append(ipRanges, ipRange{
			start: binaryIPToInt(startIP.To4()),
			end:   binaryIPToInt(endIP.To4()),
			location: GeoLocation{
				Country:     record[1],
				CountryCode: record[2],
				Sources:     []string{"geofeed"},
			},
		})
	}

	log.Printf("[INFO] Loaded %d ranges from Geofeed database", len(records))
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

// Returns the country corresponding to an IP
func lookupCountry(ip net.IP) string {
	if !isDBLoaded() {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	ipInt := binaryIPToInt(ip4)

	// Use binary search instead of linear search
	location := findIPRange(ipInt, ipRanges)
	if location != nil {
		return location.location.Country
	}
	return ""
}

// Loads the IP2Location CSV database into memory

// Rate limiting middleware per IP
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

// Gets the client's IP address
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

// Health check handler for /health
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

func incrementRequestCounter(source string) {
	requestMutex.Lock()
	defer requestMutex.Unlock()
	requestCounter[source]++
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

// Metrics handler for /metrics
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

func errorHandler(handler func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if err := handler(w, r); err != nil {
            log.Printf("[ERROR] %s %s: %v", r.Method, r.URL.Path, err)
            
            switch e := err.(type) {
            case *httpError:
                http.Error(w, e.Message, e.Code)
            default:
                http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            }
        }
    }
}

type httpError struct {
    Code    int
    Message string
}

func (e *httpError) Error() string {
    return e.Message
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

func main() {
    log.Printf("[INFO] Starting server on %s", serverPort)

    // Carica il database all'avvio
    if err := loadIPDatabases(); err != nil {
        log.Fatalf("[FATAL] Failed to load initial database: %v", err)
    }
    setDBLoaded(true)

    // Avvia il refresh periodico del database
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    go startDatabaseRefresher(ctx, 24*time.Hour)

    // Setup delle route
    mux := http.NewServeMux()
    setupRoutes(mux)

    // Avvia il server
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
