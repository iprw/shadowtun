package main

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	shadowtls "github.com/metacubex/sing-shadowtls"
	N "github.com/metacubex/sing/common/network"

	shared "shadowtls-tunnel/pkg/shadowtls"
)

const (
	dialTimeout = 30 * time.Second
	idleTimeout = 5 * time.Minute
)

func runClient(listen, server, sni, password string) {
	log.Printf("Starting ShadowTLS v3 client")
	log.Printf("Listening on: %s", listen)
	log.Printf("Server: %s", server)
	log.Printf("SNI: %s", sni)

	serverHost, serverPort := shared.ParseHostPort(server)

	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:    3,
		Password:   password,
		Server:     shared.MakeSocksaddr(serverHost, serverPort),
		Dialer:     N.SystemDialer,
		StrictMode: false,
		Logger:     &stdLogger{},
	})
	if err != nil {
		log.Fatalf("Failed to create ShadowTLS client: %v", err)
	}

	client.SetHandshakeFunc(shared.CreateHandshakeFunc(sni))

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listen, err)
	}
	defer listener.Close()

	log.Printf("Client listening on %s", listen)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleClientConn(conn, client)
	}
}

func handleClientConn(localConn net.Conn, client *shadowtls.Client) {
	defer localConn.Close()

	log.Printf("New local connection from %s", localConn.RemoteAddr())

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	tunnelConn, err := client.DialContext(ctx)
	if err != nil {
		log.Printf("Failed to establish tunnel: %v", err)
		return
	}
	defer tunnelConn.Close()

	log.Printf("Tunnel established for %s", localConn.RemoteAddr())

	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		copyWithTimeout(tunnelConn, localConn, done)
		tunnelConn.Close()
	}()

	go func() {
		defer wg.Done()
		copyWithTimeout(localConn, tunnelConn, done)
		localConn.Close()
	}()

	wg.Wait()
	close(done)
	log.Printf("Connection from %s closed", localConn.RemoteAddr())
}

func copyWithTimeout(dst, src net.Conn, done chan struct{}) {
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-done:
			return
		default:
		}

		src.SetReadDeadline(time.Now().Add(idleTimeout))

		n, err := src.Read(buf)
		if n > 0 {
			dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_, werr := dst.Write(buf[:n])
			if werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
