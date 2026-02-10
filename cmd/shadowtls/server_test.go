package main

import (
	"testing"
)

func TestNewServer(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "0.0.0.0:8443",
		ForwardAddr: "127.0.0.1:8080",
		Handshake:   "google.com:443",
		Password:    "securepass",
		WildcardSNI: false,
		Socks5Mode:  false,
	}

	server := NewServer(config)

	if server == nil {
		t.Fatal("NewServer returned nil")
	}
	if server.config != config {
		t.Error("Server config mismatch")
	}
}

func TestNewServerSocks5(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:  "0.0.0.0:8443",
		Password:    "securepass",
		Socks5Mode:  true,
		WildcardSNI: true,
	}

	server := NewServer(config)

	if server == nil {
		t.Fatal("NewServer returned nil")
	}
	if !server.config.Socks5Mode {
		t.Error("Server should be in SOCKS5 mode")
	}
}
