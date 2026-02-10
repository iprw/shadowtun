package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	mode := flag.String("mode", "", "Operation mode: server or client")
	listen := flag.String("listen", "", "Listen address (e.g., 0.0.0.0:8443 for server, 127.0.0.1:2222 for client)")
	server := flag.String("server", "", "ShadowTLS server address (client mode only)")
	forward := flag.String("forward", "", "Backend address to forward to (server mode only, e.g., localhost:22)")
	socks5Mode := flag.Bool("socks5", false, "Run SOCKS5 proxy server instead of port forward (server mode)")
	handshake := flag.String("handshake", "", "TLS handshake server for camouflage (server mode, e.g., www.google.com:443)")
	wildcardSNI := flag.Bool("wildcard-sni", false, "Use client's SNI as handshake server (server mode, makes --handshake optional)")
	password := flag.String("password", "", "Shared password for authentication")
	sni := flag.String("sni", "", "SNI for TLS handshake (client mode)")

	flag.Parse()

	if *mode == "" || *listen == "" || *password == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s --mode <server|client> --listen <addr:port> --password <secret> [options]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Server mode options:")
		fmt.Fprintln(os.Stderr, "  --forward <addr:port>    Backend to forward traffic to (e.g., localhost:22)")
		fmt.Fprintln(os.Stderr, "  --socks5                 Run SOCKS5 proxy instead of port forward")
		fmt.Fprintln(os.Stderr, "  --handshake <host:port>  TLS server for handshake camouflage (e.g., www.google.com:443)")
		fmt.Fprintln(os.Stderr, "  --wildcard-sni           Use client's SNI as handshake server (makes --handshake optional)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Client mode options:")
		fmt.Fprintln(os.Stderr, "  --server <addr:port>     ShadowTLS server address")
		fmt.Fprintln(os.Stderr, "  --sni <hostname>         SNI for TLS handshake")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  Server: shadowtls --mode server --listen 0.0.0.0:8443 --forward localhost:22 --handshake www.google.com:443 --password secret")
		fmt.Fprintln(os.Stderr, "  Client: shadowtls --mode client --listen 127.0.0.1:2222 --server example.com:8443 --sni www.google.com --password secret")
		os.Exit(1)
	}

	switch *mode {
	case "server":
		if *forward == "" && !*socks5Mode {
			log.Fatal("Server mode requires --forward or --socks5 option")
		}
		if *handshake == "" && !*wildcardSNI {
			log.Fatal("Server mode requires --handshake or --wildcard-sni option")
		}
		runServer(*listen, *forward, *handshake, *password, *wildcardSNI, *socks5Mode)
	case "client":
		if *server == "" || *sni == "" {
			log.Fatal("Client mode requires --server and --sni options")
		}
		runClient(*listen, *server, *sni, *password)
	default:
		log.Fatalf("Unknown mode: %s (use 'server' or 'client')", *mode)
	}
}
