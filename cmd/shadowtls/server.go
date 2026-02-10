package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	shadowtls "github.com/metacubex/sing-shadowtls"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	stls "github.com/iprw/shadowtun/pkg/shadowtls"
	"github.com/iprw/shadowtun/pkg/socks5"
)

const (
	serverIdleTimeout  = 5 * time.Minute
	serverWriteTimeout = 30 * time.Second
)

type forwardHandler struct {
	forward string
}

func (h *forwardHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	Log.Debugf("New authenticated connection from %s", conn.RemoteAddr())

	backend, err := net.Dial("tcp", h.forward)
	if err != nil {
		Log.Warnf("Failed to connect to backend %s: %v", h.forward, err)
		return err
	}
	defer backend.Close()

	Log.Debugf("Connected to backend %s", h.forward)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		serverCopy(backend, conn)
		if tc, ok := backend.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		serverCopy(conn, backend)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	Log.Debugf("Connection from %s closed", conn.RemoteAddr())
	return nil
}

func (h *forwardHandler) NewError(ctx context.Context, err error) {
	Log.Warnf("Handler error: %v", err)
}

// serverCopy copies data with idle and write timeouts to prevent ghost connections.
func serverCopy(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		src.SetReadDeadline(time.Now().Add(serverIdleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			dst.SetWriteDeadline(time.Now().Add(serverWriteTimeout))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

type socks5Handler struct {
	handler *socks5.Handler
}

func (h *socks5Handler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	Log.Debugf("New SOCKS5 connection from %s", conn.RemoteAddr())
	err := h.handler.Handle(ctx, conn)
	if err != nil {
		Log.Warnf("SOCKS5 error from %s: %v", conn.RemoteAddr(), err)
	}
	return err
}

func (h *socks5Handler) NewError(ctx context.Context, err error) {
	Log.Warnf("SOCKS5 handler error: %v", err)
}

func runServer(listen, forward, handshake, password string, wildcardSNI, socks5Mode bool) {
	Log.Infof("Starting ShadowTLS v3 server on %s", listen)
	if socks5Mode {
		Log.Infof("Mode: SOCKS5 proxy")
	} else {
		Log.Infof("Forwarding to: %s", forward)
	}
	if wildcardSNI {
		Log.Infof("Wildcard SNI enabled (handshake server determined by client SNI)")
	} else if handshake != "" {
		Log.Infof("Handshake server: %s", handshake)
	}

	var handler shadowtls.Handler
	if socks5Mode {
		handler = &socks5Handler{handler: socks5.NewHandler("", "", Log)}
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
		Logger:     &stls.Logger{L: Log},
	}

	if handshake != "" {
		handshakeHost, handshakePort := stls.ParseHostPort(handshake)
		config.Handshake = shadowtls.HandshakeConfig{
			Server: stls.MakeSocksaddr(handshakeHost, handshakePort),
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
		Log.Fatalf("Failed to create ShadowTLS service: %v", err)
	}

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		Log.Fatalf("Failed to listen on %s: %v", listen, err)
	}
	defer listener.Close()

	Log.Infof("Server listening on %s", listen)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		Log.Info("Shutting down...")
		cancel()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				Log.Warnf("Accept error: %v", err)
				continue
			}
			break
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			err := service.NewConnection(ctx, c, M.Metadata{})
			if err != nil {
				Log.Warnf("Connection error from %s: %v", c.RemoteAddr(), err)
			}
		}(conn)
	}

	Log.Info("Waiting for connections to close...")
	wg.Wait()
	Log.Info("Shutdown complete")
}
