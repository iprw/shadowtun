package main

import (
	"context"
	"io"
	"log"
	"net"
	"sync"

	shadowtls "github.com/metacubex/sing-shadowtls"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	shared "shadowtls-tunnel/pkg/shadowtls"
)

type forwardHandler struct {
	forward string
}

func (h *forwardHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	log.Printf("New authenticated connection from %s", conn.RemoteAddr())

	backend, err := net.Dial("tcp", h.forward)
	if err != nil {
		log.Printf("Failed to connect to backend %s: %v", h.forward, err)
		return err
	}

	log.Printf("Connected to backend %s", h.forward)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(backend, conn)
		backend.(*net.TCPConn).CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, backend)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	backend.Close()
	log.Printf("Connection from %s closed", conn.RemoteAddr())
	return nil
}

func (h *forwardHandler) NewError(ctx context.Context, err error) {
	log.Printf("Handler error: %v", err)
}

type socks5Handler struct {
	handler *SOCKS5Handler
}

func (h *socks5Handler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	log.Printf("New SOCKS5 connection from %s", conn.RemoteAddr())
	err := h.handler.Handle(ctx, conn)
	if err != nil {
		log.Printf("SOCKS5 error from %s: %v", conn.RemoteAddr(), err)
	}
	return err
}

func (h *socks5Handler) NewError(ctx context.Context, err error) {
	log.Printf("SOCKS5 handler error: %v", err)
}

// stdLogger implements the sing-shadowtls ContextLogger interface
// using the standard log package with level prefixes.
type stdLogger struct{}

func (l *stdLogger) Trace(args ...any)                             { log.Println(append([]any{"TRACE:"}, args...)...) }
func (l *stdLogger) Debug(args ...any)                             { log.Println(append([]any{"DEBUG:"}, args...)...) }
func (l *stdLogger) Info(args ...any)                              { log.Println(args...) }
func (l *stdLogger) Warn(args ...any)                              { log.Println(append([]any{"WARN:"}, args...)...) }
func (l *stdLogger) Error(args ...any)                             { log.Println(append([]any{"ERROR:"}, args...)...) }
func (l *stdLogger) Fatal(args ...any)                             { log.Fatal(args...) }
func (l *stdLogger) Panic(args ...any)                             { log.Panic(args...) }
func (l *stdLogger) TraceContext(ctx context.Context, args ...any) { log.Println(append([]any{"TRACE:"}, args...)...) }
func (l *stdLogger) DebugContext(ctx context.Context, args ...any) { log.Println(append([]any{"DEBUG:"}, args...)...) }
func (l *stdLogger) InfoContext(ctx context.Context, args ...any)  { log.Println(args...) }
func (l *stdLogger) WarnContext(ctx context.Context, args ...any)  { log.Println(append([]any{"WARN:"}, args...)...) }
func (l *stdLogger) ErrorContext(ctx context.Context, args ...any) { log.Println(append([]any{"ERROR:"}, args...)...) }
func (l *stdLogger) FatalContext(ctx context.Context, args ...any) { log.Fatal(args...) }
func (l *stdLogger) PanicContext(ctx context.Context, args ...any) { log.Panic(args...) }

func runServer(listen, forward, handshake, password string, wildcardSNI, socks5Mode bool) {
	log.Printf("Starting ShadowTLS v3 server on %s", listen)
	if socks5Mode {
		log.Printf("Mode: SOCKS5 proxy")
	} else {
		log.Printf("Forwarding to: %s", forward)
	}
	if wildcardSNI {
		log.Printf("Wildcard SNI enabled (handshake server determined by client SNI)")
	} else if handshake != "" {
		log.Printf("Handshake server: %s", handshake)
	}

	var handler shadowtls.Handler
	if socks5Mode {
		handler = &socks5Handler{handler: NewSOCKS5Handler("", "")}
	} else {
		handler = &forwardHandler{forward: forward}
	}

	config := shadowtls.ServiceConfig{
		Version: 3,
		Users: []shadowtls.User{
			{Name: "default", Password: password},
		},
		StrictMode: false,
		Handler:    handler,
		Logger:     &stdLogger{},
	}

	if handshake != "" {
		handshakeHost, handshakePort := shared.ParseHostPort(handshake)
		config.Handshake = shadowtls.HandshakeConfig{
			Server: shared.MakeSocksaddr(handshakeHost, handshakePort),
			Dialer: N.SystemDialer,
		}
	} else {
		config.Handshake = shadowtls.HandshakeConfig{
			Dialer: N.SystemDialer,
		}
	}

	if wildcardSNI {
		config.WildcardSNI = shadowtls.WildcardSNIAuthed
	}

	service, err := shadowtls.NewService(config)
	if err != nil {
		log.Fatalf("Failed to create ShadowTLS service: %v", err)
	}

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listen, err)
	}
	defer listener.Close()

	log.Printf("Server listening on %s", listen)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go func(c net.Conn) {
			defer c.Close()
			ctx := context.Background()
			err := service.NewConnection(ctx, c, M.Metadata{})
			if err != nil {
				log.Printf("Connection error from %s: %v", c.RemoteAddr(), err)
			}
		}(conn)
	}
}
