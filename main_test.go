package main

import (
	"net"
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
