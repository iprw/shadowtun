package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	shadowtls "github.com/metacubex/sing-shadowtls"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/sirupsen/logrus"

	relaypkg "github.com/iprw/shadowtun/pkg/relay"
	stls "github.com/iprw/shadowtun/pkg/shadowtls"
	"github.com/iprw/shadowtun/pkg/socks5"
)

type forwardHandler struct {
	forward string
	logger  *logrus.Logger
}

func (h *forwardHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	h.logger.Debugf("New authenticated connection from %s", conn.RemoteAddr())

	backend, err := net.Dial("tcp", h.forward)
	if err != nil {
		h.logger.Warnf("Failed to connect to backend %s: %v", h.forward, err)
		return err
	}
	defer backend.Close()

	h.logger.Debugf("Connected to backend %s", h.forward)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		relaypkg.CopyConn(backend, conn, relaypkg.DefaultIdleTimeout, relaypkg.DefaultWriteTimeout, nil)
		if tc, ok := backend.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		relaypkg.CopyConn(conn, backend, relaypkg.DefaultIdleTimeout, relaypkg.DefaultWriteTimeout, nil)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	h.logger.Debugf("Connection from %s closed", conn.RemoteAddr())
	return nil
}

func (h *forwardHandler) NewError(ctx context.Context, err error) {
	h.logger.Warnf("Handler error: %v", err)
}

type socks5Handler struct {
	handler *socks5.Handler
	logger  *logrus.Logger
}

func (h *socks5Handler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	h.logger.Debugf("New SOCKS5 connection from %s", conn.RemoteAddr())
	err := h.handler.Handle(ctx, conn)
	if err != nil {
		h.logger.Warnf("SOCKS5 error from %s: %v", conn.RemoteAddr(), err)
	}
	return err
}

func (h *socks5Handler) NewError(ctx context.Context, err error) {
	h.logger.Warnf("SOCKS5 handler error: %v", err)
}

// ServerConfig holds configuration for the ShadowTLS server
type ServerConfig struct {
	ListenAddr  string
	ForwardAddr string
	Handshake   string
	Password    string
	WildcardSNI bool
	Socks5Mode  bool
	Logger      *logrus.Logger
}

// Server represents a ShadowTLS server instance
type Server struct {
	config *ServerConfig
	log    *logrus.Logger
}

// NewServer creates a new server instance
func NewServer(config *ServerConfig) *Server {
	logger := config.Logger
	if logger == nil {
		logger = Log // Fallback to global logger
	}
	return &Server{
		config: config,
		log:    logger,
	}
}

// Run starts the server and blocks until shutdown
func (s *Server) Run() error {
	s.log.Infof("Starting ShadowTLS v3 server on %s", s.config.ListenAddr)
	if s.config.Socks5Mode {
		s.log.Infof("Mode: SOCKS5 proxy")
	} else {
		s.log.Infof("Forwarding to: %s", s.config.ForwardAddr)
	}
	if s.config.WildcardSNI {
		s.log.Infof("Wildcard SNI enabled (handshake server determined by client SNI)")
	} else if s.config.Handshake != "" {
		s.log.Infof("Handshake server: %s", s.config.Handshake)
	}

	var handler shadowtls.Handler
	if s.config.Socks5Mode {
		handler = &socks5Handler{
			handler: socks5.NewHandler("", "", s.log),
			logger:  s.log,
		}
	} else {
		handler = &forwardHandler{
			forward: s.config.ForwardAddr,
			logger:  s.log,
		}
	}

	config := shadowtls.ServiceConfig{
		Version: 3,
		Users: []shadowtls.User{
			{Name: "default", Password: s.config.Password},
		},
		StrictMode: false,
		Handler:    handler,
		Logger:     &stls.Logger{L: s.log},
	}

	if s.config.Handshake != "" {
		handshakeHost, handshakePort := stls.ParseHostPort(s.config.Handshake)
		config.Handshake = shadowtls.HandshakeConfig{
			Server: stls.MakeSocksaddr(handshakeHost, handshakePort),
			Dialer: N.SystemDialer,
		}
	} else {
		config.Handshake = shadowtls.HandshakeConfig{
			Dialer: N.SystemDialer,
		}
	}

	if s.config.WildcardSNI {
		config.WildcardSNI = shadowtls.WildcardSNIAuthed
	}

	service, err := shadowtls.NewService(config)
	if err != nil {
		return fmt.Errorf("failed to create ShadowTLS service: %v", err)
	}

	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", s.config.ListenAddr, err)
	}
	defer listener.Close()

	s.log.Infof("Server listening on %s", s.config.ListenAddr)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		s.log.Info("Shutting down...")
		cancel()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				s.log.Warnf("Accept error: %v", err)
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
				s.log.Warnf("Connection error from %s: %v", c.RemoteAddr(), err)
			}
		}(conn)
	}

	s.log.Info("Waiting for connections to close...")
	wg.Wait()
	s.log.Info("Shutdown complete")
	return nil
}
