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

	stls "github.com/iprw/shadowtun/pkg/shadowtls"
)

var globalStats *Stats

const (
	idleTimeout   = 5 * time.Minute
	writeTimeout  = 30 * time.Second
	verifyTimeout = 5 * time.Second
	copyBufSize   = 32 * 1024
	maxRetries    = 3
)

func runClient(listen, server, sni, password string, poolSize int, ttl, backoff, timeout, statsInterval time.Duration) {
	globalStats = NewStats()

	client, err := stls.NewClient(server, sni, password, timeout, Log)
	if err != nil {
		Log.Fatalf("Failed to create ShadowTLS client: %v", err)
	}

	factory := &stls.Factory{
		Client: client,
	}

	pool := NewConnPool(poolSize, ttl, backoff, factory.Create, globalStats)
	pool.Start()

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		Log.Fatalf("Failed to listen on %s: %v", listen, err)
	}

	Log.Infof("shadowtls client started")
	Log.Infof("  Listen: %s", listen)
	Log.Infof("  Server: %s", server)
	Log.Infof("  SNI: %s", sni)
	Log.Infof("  Pool size: %d, TTL: %v, Backoff: %v", poolSize, ttl, backoff)
	if statsInterval > 0 {
		Log.Infof("  Stats interval: %v", statsInterval)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGUSR1:
				avail, cap := pool.Stats()
				snap := globalStats.Snapshot(avail, cap)
				fmt.Println(snap.String())
			case syscall.SIGINT, syscall.SIGTERM:
				Log.Info("Shutting down...")
				cancel()
				listener.Close()
				return
			}
		}
	}()

	if statsInterval > 0 {
		go func() {
			ticker := time.NewTicker(statsInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					avail, cap := pool.Stats()
					snap := globalStats.Snapshot(avail, cap)
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
		go func(c net.Conn) {
			defer wg.Done()
			handleConnection(ctx, c, pool, globalStats)
		}(conn)
	}

	Log.Info("Waiting for connections to close...")
	wg.Wait()
	pool.Stop()

	avail, cap := pool.Stats()
	snap := globalStats.Snapshot(avail, cap)
	fmt.Println(snap.String())

	Log.Info("Shutdown complete")
}

func handleConnection(ctx context.Context, local net.Conn, pool *ConnPool, stats *Stats) {
	connStart := time.Now()
	stats.ConnStart()
	defer func() {
		stats.ConnEnd()
		stats.RecordConnLifetime(time.Since(connStart))
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
		stats.ConnErrors.Add(1)
		return
	}
	initialData := initialBuf[:n]

	// Get a verified tunnel, retrying stale connections
	tunnel, firstResponse, err := acquireTunnel(ctx, pool, stats, initialData)
	if err != nil {
		Log.Warnf("Failed to get tunnel: %v", err)
		stats.ConnErrors.Add(1)
		return
	}
	defer tunnel.Close()

	// Forward the server's first response to the local client
	local.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err = local.Write(firstResponse)
	local.SetWriteDeadline(time.Time{})
	if err != nil {
		Log.Debugf("Failed to forward response to client: %v", err)
		stats.ConnErrors.Add(1)
		return
	}

	// Bidirectional relay
	bytesOut, bytesIn := relay(ctx, local, tunnel, stats)

	Log.Infof("Connection closed: %s out, %s in, %v",
		formatBytesShort(int64(len(initialData))+bytesOut),
		formatBytesShort(int64(len(firstResponse))+bytesIn),
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
		src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			dst.SetWriteDeadline(time.Now().Add(writeTimeout))
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
