package main

import (
	"context"
	"net"
	"time"

	shadowtls "github.com/metacubex/sing-shadowtls"
	N "github.com/metacubex/sing/common/network"

	shared "shadowtls-tunnel/pkg/shadowtls"
)

// ShadowTLSClient wraps the sing-shadowtls client
type ShadowTLSClient struct {
	client  *shadowtls.Client
	timeout time.Duration
}

// NewShadowTLSClient creates a new ShadowTLS client
func NewShadowTLSClient(server, sni, password string, timeout time.Duration) (*ShadowTLSClient, error) {
	serverHost, serverPort := shared.ParseHostPort(server)

	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:    3,
		Password:   password,
		Server:     shared.MakeSocksaddr(serverHost, serverPort),
		Dialer:     N.SystemDialer,
		StrictMode: false,
		Logger:     &ShadowTLSLogger{},
	})
	if err != nil {
		return nil, err
	}

	client.SetHandshakeFunc(shared.CreateHandshakeFunc(sni))

	return &ShadowTLSClient{
		client:  client,
		timeout: timeout,
	}, nil
}

// Dial establishes a new ShadowTLS connection
func (c *ShadowTLSClient) Dial(ctx context.Context) (net.Conn, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	return c.client.DialContext(ctx)
}

// ShadowTLSFactory creates ShadowTLS connections for the pool
type ShadowTLSFactory struct {
	client  *ShadowTLSClient
	timeout time.Duration
}

// Create creates a new ShadowTLS connection
func (f *ShadowTLSFactory) Create(ctx context.Context) (net.Conn, error) {
	start := time.Now()
	conn, err := f.client.Dial(ctx)
	if err != nil {
		return nil, err
	}
	Log.Tracef("ShadowTLS connection established in %v", time.Since(start))
	return conn, nil
}
