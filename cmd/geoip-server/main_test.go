package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBinaryIPToInt(t *testing.T) {
	ip := net.ParseIP("1.2.3.4").To4()
	if ip == nil {
		t.Fatal("failed to parse IPv4")
	}
	got := binaryIPToInt(ip)
	want := uint32(1<<24 | 2<<16 | 3<<8 | 4)
	if got != want {
		t.Fatalf("binaryIPToInt = %d, want %d", got, want)
	}
}

func TestFindIPRange(t *testing.T) {
	ranges := []ipRange{
		{start: 10, end: 20},
		{start: 30, end: 40},
		{start: 50, end: 60},
	}
	// a value in the second range
	ip := uint32(35)
	r := findIPRange(ip, ranges)
	if r == nil {
		t.Fatalf("expected to find range for %d", ip)
	}
	if r.start != 30 || r.end != 40 {
		t.Fatalf("unexpected range found: %+v", r)
	}
}

func TestSanitizeCoords(t *testing.T) {
	lat := 0.0
	lon := 12.34
	sanitizeCoords(&lat, &lon)
	if lat != 0 || lon != 0 {
		t.Fatalf("expected coords zeroed when one zero: got %v,%v", lat, lon)
	}

	lat = 45.0
	lon = 90.0
	sanitizeCoords(&lat, &lon)
	if lat != 45.0 || lon != 90.0 {
		t.Fatalf("expected coords preserved: got %v,%v", lat, lon)
	}

	// test cache helpers quickly
	setCachedResponse("k", []byte("v"), 1*time.Second)
	if d, ok := getCachedResponse("k"); !ok || string(d) != "v" {
		t.Fatalf("cache miss or wrong value: %v %v", ok, string(d))
	}
}


func TestGetIPWithXFF(t *testing.T) {
	// X-Forwarded-For is always trusted
	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if ip := getIP(req); ip != "1.2.3.4" {
		t.Fatalf("expected forwarded IP 1.2.3.4, got %s", ip)
	}
}

func TestGetIPFallbackToRemoteAddr(t *testing.T) {
	// No X-Forwarded-For: fall back to RemoteAddr
	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	if ip := getIP(req); ip != "10.0.0.1" {
		t.Fatalf("expected RemoteAddr 10.0.0.1, got %s", ip)
	}
}

func TestHandlerBulkLookup_InvalidMethod(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/lookup", nil)
	rr := httptest.NewRecorder()
	handlerBulkLookup(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestHandlerBulkLookup_TooManyIPs(t *testing.T) {
	ips := make([]string, 101)
	for i := range ips {
		ips[i] = `"1.1.1.1"`
	}
	body := strings.NewReader(`{"ips":[` + strings.Join(ips, ",") + `]}`)
	req, _ := http.NewRequest("POST", "/api/lookup", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handlerBulkLookup(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandlerBulkLookup_EmptyList(t *testing.T) {
	body := strings.NewReader(`{"ips":[]}`)
	req, _ := http.NewRequest("POST", "/api/lookup", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handlerBulkLookup(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestHandlerBulkLookup_InvalidIP(t *testing.T) {
	body := strings.NewReader(`{"ips":["not-an-ip"]}`)
	req, _ := http.NewRequest("POST", "/api/lookup", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handlerBulkLookup(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "error:invalid-ip") {
		t.Fatalf("expected error:invalid-ip in response, got: %s", rr.Body.String())
	}
}

func TestCORSOptionsHeader(t *testing.T) {
	req, _ := http.NewRequest("OPTIONS", "/api/myip", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	rateLimitMiddleware(http.HandlerFunc(handlerJSON)).ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS preflight expected 204, got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("missing Access-Control-Allow-Origin header")
	}
}
