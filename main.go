package main

import (
	"encoding/csv"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	serverPort     = "0.0.0.0:8080" // Listen on all interfaces
	requestLimit   = 10
	windowDuration = time.Minute
	dbFile         = "ip2location.csv"
)

type ipRange struct {
	start   uint32
	end     uint32
	country string
}

type clientData struct {
	timestamps []time.Time
	mu         sync.Mutex // Protects timestamps per client
}

var (
	ipRanges      []ipRange
	statsMu       sync.RWMutex
	clientStats   = make(map[string]*clientData)
	dbLoaded      bool // Indicates if the database was loaded successfully
	dbLoadedMutex sync.RWMutex
)

func main() {
	err := loadIPDatabase(dbFile)
	if err != nil {
		log.Printf("[WARN] Failed to load IP2Location database: %v. Country lookup will be disabled.", err)
		setDBLoaded(false)
	} else {
		setDBLoaded(true)
		log.Printf("[INFO] IP2Location database loaded successfully.")
	}

	mux := http.NewServeMux()
	mux.Handle("/ip", rateLimitMiddleware(http.HandlerFunc(handlerJSON)))
	mux.Handle("/ip/plain", rateLimitMiddleware(http.HandlerFunc(handlerPlain)))
	mux.Handle("/health", http.HandlerFunc(healthHandler))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ip", http.StatusTemporaryRedirect)
		logRequest(r, http.StatusTemporaryRedirect, " [redirect to /ip]")
	})

	server := &http.Server{
		Addr:         serverPort,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Printf("[INFO] Server started on %s", serverPort)
	log.Fatal(server.ListenAndServe())
}

// Loads the IP2Location CSV database into memory
func loadIPDatabase(path string) error {
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
			log.Printf("[WARN] Row %d ignored (only %d columns)", i+1, len(record))
			continue
		}

		startIP, err1 := strconv.ParseUint(record[0], 10, 32)
		endIP, err2 := strconv.ParseUint(record[1], 10, 32)
		if err1 != nil || err2 != nil {
			log.Printf("[WARN] Row %d has invalid IPs", i+1)
			continue
		}

		country := record[2]

		ipRanges = append(ipRanges, ipRange{
			start:   uint32(startIP),
			end:     uint32(endIP),
			country: country,
		})
	}

	log.Printf("[INFO] Loaded %d IP ranges from IP2Location database", len(ipRanges))
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

	// Linear search (can be optimized with binary search)
	for _, rng := range ipRanges {
		if ipInt >= rng.start && ipInt <= rng.end {
			return rng.country
		}
	}
	return ""
}

func binaryIPToInt(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// Rate limiting middleware per IP
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getIP(r)
		if ip == "" {
			log.Printf("[ERROR] Invalid IP address in request - UA: %q", r.UserAgent())
			http.Error(w, "Invalid IP address", http.StatusBadRequest)
			logRequest(r, http.StatusBadRequest, " [invalid ip]")
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
			logRequest(r, http.StatusTooManyRequests, " [rate limit]")
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

func logRequest(r *http.Request, status int, extra string) {
	ip := getIP(r)
	ua := r.UserAgent()
	log.Printf("[INFO] %s %s - IP: %s - UA: %q - Status: %d%s",
		r.Method, r.URL.Path, ip, ua, status, extra)
}

// JSON handler for /api/myip
func handlerJSON(w http.ResponseWriter, r *http.Request) {
	ipStr := getIP(r)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Printf("[ERROR] Invalid IP address in handlerJSON - UA: %q", r.UserAgent())
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		logRequest(r, http.StatusBadRequest, " [invalid ip]")
		return
	}

	resp := map[string]string{
		"ip": ipStr,
	}
	country := lookupCountry(ip)
	if country != "" {
		resp["country"] = country
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	logRequest(r, http.StatusOK, "")
}

// Plain text handler for /api/myip/plain
func handlerPlain(w http.ResponseWriter, r *http.Request) {
	ipStr := getIP(r)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Printf("[ERROR] Invalid IP address in handlerPlain - UA: %q", r.UserAgent())
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		logRequest(r, http.StatusBadRequest, " [invalid ip]")
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(ipStr))
	logRequest(r, http.StatusOK, "")
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
	logRequest(r, http.StatusOK, "")
}
