package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	relaypkg "github.com/iprw/shadowtun/pkg/relay"
	stls "github.com/iprw/shadowtun/pkg/shadowtls"
)

const (
	verifyTimeout = 5 * time.Second
	copyBufSize   = 32 * 1024
	maxRetries    = 3
)

// ClientConfig holds configuration for the ShadowTLS client
type ClientConfig struct {
	ListenAddr    string
	ServerAddr    string
	SNI           string
	Password      string
	PoolSize      int
	TTL           time.Duration
	Backoff       time.Duration
	Timeout       time.Duration
	StatsInterval time.Duration
	Logger        *logrus.Logger
}

// Client represents a ShadowTLS client instance
type Client struct {
	config *ClientConfig
	stats  *Stats
	pool   *ConnPool
	log    *logrus.Logger
}

// NewClient creates a new client instance
func NewClient(config *ClientConfig) *Client {
	logger := config.Logger
	if logger == nil {
		logger = Log // Fallback to global logger if not provided
	}
	return &Client{
		config: config,
		stats:  NewStats(),
		log:    logger,
	}
}

func (c *Client) Run() error {
	client, err := stls.NewClient(c.config.ServerAddr, c.config.SNI, c.config.Password, c.config.Timeout, c.log)
	if err != nil {
		return fmt.Errorf("failed to create ShadowTLS client: %v", err)
	}

	factory := &stls.Factory{
		Client: client,
	}

	c.pool = NewConnPool(c.config.PoolSize, c.config.TTL, c.config.Backoff, factory.Create, c.stats)
	c.pool.Start()

	listener, err := net.Listen("tcp", c.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", c.config.ListenAddr, err)
	}

	c.log.Infof("shadowtls client started")
	c.log.Infof("  Listen: %s", c.config.ListenAddr)
	c.log.Infof("  Server: %s", c.config.ServerAddr)
	c.log.Infof("  SNI: %s", c.config.SNI)
	c.log.Infof("  Pool size: %d, TTL: %v, Backoff: %v", c.config.PoolSize, c.config.TTL, c.config.Backoff)
	if c.config.StatsInterval > 0 {
		c.log.Infof("  Stats interval: %v", c.config.StatsInterval)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGUSR1:
				avail, cap := c.pool.Stats()
				snap := c.stats.Snapshot(avail, cap)
				fmt.Println(snap.String())
			case syscall.SIGINT, syscall.SIGTERM:
				Log.Info("Shutting down...")
				cancel()
				listener.Close()
				return
			}
		}
	}()

	if c.config.StatsInterval > 0 {
		go func() {
			ticker := time.NewTicker(c.config.StatsInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					avail, cap := c.pool.Stats()
					snap := c.stats.Snapshot(avail, cap)
					snap.Log()
				case <-ctx.Done():
					return
				}
			}
		}()
	}

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
		go func(c_conn net.Conn) {
			defer wg.Done()
			c.handleConnection(ctx, c_conn)
		}(conn)
	}

	Log.Info("Waiting for connections to close...")
	wg.Wait()
	c.pool.Stop()

	avail, cap := c.pool.Stats()
	snap := c.stats.Snapshot(avail, cap)
	fmt.Println(snap.String())

	Log.Info("Shutdown complete")
	return nil
}

func (c *Client) handleConnection(ctx context.Context, local net.Conn) {
	connStart := time.Now()
	c.stats.ConnStart()
	defer func() {
		c.stats.ConnEnd()
		c.stats.RecordConnLifetime(time.Since(connStart))
	}()
	defer local.Close()

	Log.Debugf("New connection from %s", local.RemoteAddr())

	// Read initial data from client for replay on stale pool connections.
	initialBuf := make([]byte, copyBufSize)
	local.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := local.Read(initialBuf)
	local.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		Log.Debugf("No initial data from %s: %v", local.RemoteAddr(), err)
		c.stats.ConnErrors.Add(1)
		return
	}
	initialData := initialBuf[:n]

	// Get a verified tunnel, retrying stale connections
	tunnel, firstResponse, err := acquireTunnel(ctx, c.pool, c.stats, initialData)
	if err != nil {
		Log.Warnf("Failed to get tunnel: %v", err)
		c.stats.ConnErrors.Add(1)
		return
	}
	defer tunnel.Close()

	// Forward the server's first response to the local client
	local.SetWriteDeadline(time.Now().Add(relaypkg.DefaultWriteTimeout))
	_, err = local.Write(firstResponse)
	local.SetWriteDeadline(time.Time{})
	if err != nil {
		Log.Debugf("Failed to forward response to client: %v", err)
		c.stats.ConnErrors.Add(1)
		return
	}

	// Bidirectional relay
	bytesOut, bytesIn := relay(ctx, local, tunnel, c.stats)

	Log.Infof("Connection closed: %s out, %s in, %v",
		formatBytes(uint64(int64(len(initialData))+bytesOut), true),
		formatBytes(uint64(int64(len(firstResponse))+bytesIn), true),
		time.Since(connStart).Round(time.Millisecond))
}

// acquireTunnel gets a pool connection and verifies it with a full round-trip:
// write the client's initial data and read the server's response.
// TCP-dead connections fail on write; app-dead connections (expired ShadowTLS
// session) fail on read (server silently drops data, no response comes).
// Retries up to maxRetries times on stale connections.
func acquireTunnel(ctx context.Context, pool *ConnPool, stats *Stats, initialData []byte) (*PooledConn, []byte, error) {
	getCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	respBuf := make([]byte, copyBufSize)

	for attempt := 0; attempt < maxRetries; attempt++ {
		tunnel, err := pool.Get(getCtx)
		if err != nil {
			return nil, nil, err
		}

		if tunnel.FromPool {
			Log.Debugf("Tunnel: pooled (age=%v, rtt=%v)", tunnel.PoolAge.Round(time.Millisecond), tunnel.ConnectTime.Round(time.Millisecond))
		} else {
			Log.Debugf("Tunnel: new (rtt=%v)", tunnel.ConnectTime.Round(time.Millisecond))
		}

		// Write — catches TCP-dead connections
		tunnel.SetWriteDeadline(time.Now().Add(verifyTimeout))
		_, err = tunnel.Write(initialData)
		tunnel.SetWriteDeadline(time.Time{})
		if err != nil {
			stats.PoolStale.Add(1)
			Log.Debugf("Stale tunnel (write failed, %d/%d): %v", attempt+1, maxRetries, err)
			tunnel.Close()
			continue
		}

		// Read — catches app-dead connections (TCP alive, ShadowTLS session expired)
		tunnel.SetReadDeadline(time.Now().Add(verifyTimeout))
		n, err := tunnel.Read(respBuf)
		tunnel.SetReadDeadline(time.Time{})
		if err != nil || n == 0 {
			stats.PoolStale.Add(1)
			Log.Debugf("Stale tunnel (no response, %d/%d): %v", attempt+1, maxRetries, err)
			tunnel.Close()
			continue
		}

		return tunnel, respBuf[:n], nil
	}

	return nil, nil, fmt.Errorf("all %d pool connections stale", maxRetries)
}

// relay copies data bidirectionally between local and tunnel until one side
// closes or ctx is cancelled. Returns bytes sent out and received in.
func relay(ctx context.Context, local, tunnel net.Conn, stats *Stats) (bytesOut, bytesIn int64) {
	// Close both connections on shutdown; connDone prevents this goroutine
	// from leaking when the connection closes normally before shutdown.
	connDone := make(chan struct{})
	defer close(connDone)
	go func() {
		select {
		case <-ctx.Done():
			local.Close()
			tunnel.Close()
		case <-connDone:
		}
	}()

	done := make(chan struct{}, 2)

	go func() {
		bytesOut = copyConn(tunnel, local, stats) // local → tunnel
		tunnel.Close()                            // unblock tunnel → local
		done <- struct{}{}
	}()

	go func() {
		bytesIn = copyConn(local, tunnel, stats) // tunnel → local
		local.Close()                            // unblock local → tunnel
		done <- struct{}{}
	}()

	<-done
	<-done
	return
}

func copyConn(dst, src net.Conn, stats *Stats) int64 {
	buf := make([]byte, copyBufSize)
	var total int64
	for {
		src.SetReadDeadline(time.Now().Add(relaypkg.DefaultIdleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			dst.SetWriteDeadline(time.Now().Add(relaypkg.DefaultWriteTimeout))
			written, werr := dst.Write(buf[:n])
			if written > 0 {
				total += int64(written)
				stats.AddBytes(uint64(written))
			}
			if werr != nil {
				return total
			}
		}
		if err != nil {
			return total
		}
	}
}
