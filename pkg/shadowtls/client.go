package shadowtls

import (
	"context"
	"net"
	"time"

	sing_shadowtls "github.com/metacubex/sing-shadowtls"
	N "github.com/metacubex/sing/common/network"
	"github.com/sirupsen/logrus"
)

// Client wraps the sing-shadowtls client with timeout support.
type Client struct {
	client  *sing_shadowtls.Client
	timeout time.Duration
	logger  *logrus.Logger
}

// NewClient creates a new ShadowTLS v3 client.
func NewClient(server, sni, password string, timeout time.Duration, logger *logrus.Logger) (*Client, error) {
	serverHost, serverPort := ParseHostPort(server)

	client, err := sing_shadowtls.NewClient(sing_shadowtls.ClientConfig{
		Version:    3,
		Password:   password,
		Server:     MakeSocksaddr(serverHost, serverPort),
		Dialer:     N.SystemDialer,
		StrictMode: false,
		Logger:     &Logger{L: logger},
	})
	if err != nil {
		return nil, err
	}

	client.SetHandshakeFunc(CreateHandshakeFunc(sni))

	return &Client{
		client:  client,
		timeout: timeout,
		logger:  logger,
	}, nil
}

// Dial establishes a new ShadowTLS connection.
func (c *Client) Dial(ctx context.Context) (net.Conn, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	return c.client.DialContext(ctx)
}

// Factory creates ShadowTLS connections for the pool.
type Factory struct {
	Client *Client
}

// Create establishes a new ShadowTLS connection.
func (f *Factory) Create(ctx context.Context) (net.Conn, error) {
	start := time.Now()
	conn, err := f.Client.Dial(ctx)
	if err != nil {
		return nil, err
	}
	f.Client.logger.Tracef("ShadowTLS connection established in %v", time.Since(start))
	return conn, nil
}
