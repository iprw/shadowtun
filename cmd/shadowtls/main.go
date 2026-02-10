package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	// Parse verbosity first (before flag.Parse to count -v flags)
	// This removes -v, -vv, -vvv from args so flag.Parse doesn't complain
	verbosity, filteredArgs := ParseVerbosity(os.Args[1:])
	os.Args = append([]string{os.Args[0]}, filteredArgs...)

	// Mode selection
	mode := flag.String("mode", "", "Operation mode: server or client")

	// Common flags
	listen := flag.String("listen", "", "Listen address")
	password := flag.String("password", "", "Shared password for authentication")

	// Server flags
	forward := flag.String("forward", "", "Backend address to forward to (server mode)")
	socks5Mode := flag.Bool("socks5", false, "Run SOCKS5 proxy instead of port forward (server mode)")
	handshake := flag.String("handshake", "", "TLS handshake server (server mode)")
	wildcardSNI := flag.Bool("wildcard-sni", false, "Use client's SNI as handshake server (server mode)")

	// Client flags
	server := flag.String("server", "", "ShadowTLS server address (client mode)")
	sni := flag.String("sni", "", "SNI for TLS handshake (client mode)")
	poolSize := flag.Int("pool-size", 10, "Connection pool size (client mode)")
	ttl := flag.Duration("ttl", 10*time.Second, "Connection TTL (client mode)")
	backoff := flag.Duration("backoff", 5*time.Second, "Backoff on failure (client mode)")
	timeout := flag.Duration("timeout", 10*time.Second, "Connection timeout (client mode)")
	statsInterval := flag.Duration("stats-interval", 10*time.Second, "Stats interval, 0 to disable (client mode)")

	flag.Parse()

	// Initialize logging with parsed verbosity
	InitLogging(verbosity)

	if *mode == "" || *password == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s --mode <server|client> --password <secret> [options]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Server mode options:")
		fmt.Fprintln(os.Stderr, "  --listen <addr:port>     Listen address (e.g., 0.0.0.0:8443)")
		fmt.Fprintln(os.Stderr, "  --forward <addr:port>    Backend to forward traffic to")
		fmt.Fprintln(os.Stderr, "  --socks5                 Run SOCKS5 proxy instead of port forward")
		fmt.Fprintln(os.Stderr, "  --handshake <host:port>  TLS server for handshake camouflage")
		fmt.Fprintln(os.Stderr, "  --wildcard-sni           Use client's SNI as handshake server")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Client mode options:")
		fmt.Fprintln(os.Stderr, "  --listen <addr:port>     Listen address (default: 127.0.0.1:1080)")
		fmt.Fprintln(os.Stderr, "  --server <addr:port>     ShadowTLS server address")
		fmt.Fprintln(os.Stderr, "  --sni <hostname>         SNI for TLS handshake")
		fmt.Fprintln(os.Stderr, "  --pool-size <n>          Connection pool size (default: 10)")
		fmt.Fprintln(os.Stderr, "  --ttl <duration>         Connection TTL (default: 10s)")
		fmt.Fprintln(os.Stderr, "  --backoff <duration>     Retry backoff (default: 5s)")
		fmt.Fprintln(os.Stderr, "  --timeout <duration>     Connection timeout (default: 10s)")
		fmt.Fprintln(os.Stderr, "  --stats-interval <dur>   Stats logging interval (default: 10s, 0=disable)")
		fmt.Fprintln(os.Stderr, "  -v, -vv, -vvv            Log verbosity (info/debug/trace)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  Server: shadowtls --mode server --listen 0.0.0.0:8443 --socks5 --handshake www.google.com:443 --password secret")
		fmt.Fprintln(os.Stderr, "  Client: shadowtls --mode client --server example.com:8443 --sni www.google.com --password secret -vvv")
		os.Exit(1)
	}

	switch *mode {
	case "server":
		if *listen == "" {
			Log.Fatal("Server mode requires --listen")
		}
		if *forward == "" && !*socks5Mode {
			Log.Fatal("Server mode requires --forward or --socks5")
		}
		if *forward != "" && *socks5Mode {
			Log.Warn("Both --forward and --socks5 set; --socks5 takes precedence")
		}
		if *handshake == "" && !*wildcardSNI {
			Log.Fatal("Server mode requires --handshake or --wildcard-sni")
		}
		serverConfig := &ServerConfig{
			ListenAddr:  *listen,
			ForwardAddr: *forward,
			Handshake:   *handshake,
			Password:    *password,
			WildcardSNI: *wildcardSNI,
			Socks5Mode:  *socks5Mode,
			Logger:      Log,
		}
		server := NewServer(serverConfig)
		if err := server.Run(); err != nil {
			Log.Fatalf("Server error: %v", err)
		}
	case "client":
		if *server == "" || *sni == "" {
			Log.Fatal("Client mode requires --server and --sni")
		}
		if *listen == "" {
			*listen = "127.0.0.1:1080"
		}
		clientConfig := &ClientConfig{
			ListenAddr:    *listen,
			ServerAddr:    *server,
			SNI:           *sni,
			Password:      *password,
			PoolSize:      *poolSize,
			TTL:           *ttl,
			Backoff:       *backoff,
			Timeout:       *timeout,
			StatsInterval: *statsInterval,
			Logger:        Log,
		}
		client := NewClient(clientConfig)
		if err := client.Run(); err != nil {
			Log.Fatalf("Client error: %v", err)
		}
	default:
		Log.Fatalf("Unknown mode: %s (use 'server' or 'client')", *mode)
	}
}
