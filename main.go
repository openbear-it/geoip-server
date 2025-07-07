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
	ipRanges    []ipRange
	statsMu     sync.RWMutex
	clientStats = make(map[string]*clientData)
)

func main() {
	err := loadIPDatabase(dbFile)
	if err != nil {
		log.Fatalf("Failed to load IP2Location database: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", rateLimitMiddleware(http.HandlerFunc(handler)))

	server := &http.Server{
		Addr:         serverPort,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Printf("Server started on %s", serverPort)
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
			log.Printf("⚠️  Row %d ignored (only %d columns)", i+1, len(record))
			continue
		}

		startIP, err1 := strconv.ParseUint(record[0], 10, 32)
		endIP, err2 := strconv.ParseUint(record[1], 10, 32)
		if err1 != nil || err2 != nil {
			log.Printf("⚠️  Row %d has invalid IPs", i+1)
			continue
		}

		country := record[2]

		ipRanges = append(ipRanges, ipRange{
			start:   uint32(startIP),
			end:     uint32(endIP),
			country: country,
		})
	}

	log.Printf("Loaded %d IP ranges from IP2Location database", len(ipRanges))
	return nil
}

// Returns the country corresponding to an IP
func lookupCountry(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return "Unknown"
	}
	ipInt := binaryIPToInt(ip4)

	// Linear search (can be optimized with binary search)
	for _, rng := range ipRanges {
		if ipInt >= rng.start && ipInt <= rng.end {
			return rng.country
		}
	}
	return "Unknown"
}

func binaryIPToInt(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// Rate limiting middleware per IP
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getIP(r)
		if ip == "" {
			http.Error(w, "Invalid IP address", http.StatusBadRequest)
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
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		data.timestamps = append(data.timestamps, now)
		data.mu.Unlock()

		// Add security headers
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

// Main handler
func handler(w http.ResponseWriter, r *http.Request) {
	ipStr := getIP(r)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	country := lookupCountry(ip)

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]string{
		"ip":      ipStr,
		"country": country,
	}
	json.NewEncoder(w).Encode(resp)
}
