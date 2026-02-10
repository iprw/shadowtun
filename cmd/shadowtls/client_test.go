package main

import (
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	config := &ClientConfig{
		ListenAddr:    "127.0.0.1:1080",
		ServerAddr:    "127.0.0.1:8443",
		SNI:           "example.com",
		Password:      "securepass",
		PoolSize:      5,
		TTL:           10 * time.Second,
		Backoff:       5 * time.Second,
		Timeout:       5 * time.Second,
		StatsInterval: 0,
	}

	client := NewClient(config)

	if client == nil {
		t.Fatal("NewClient returned nil")
	}
	if client.config != config {
		t.Error("Client config mismatch")
	}
	if client.stats == nil {
		t.Error("Client stats not initialized")
	}
}
