package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var globalStats *Stats

func main() {
	// Parse verbosity first (before flag.Parse to count -v flags)
	// This removes -v, -vv, -vvv from args so flag.Parse doesn't complain
	verbosity, filteredArgs := ParseVerbosity(os.Args[1:])
	os.Args = append([]string{os.Args[0]}, filteredArgs...)

	// Connection settings
	listen := flag.String("listen", "127.0.0.1:2222", "Local listen address")
	server := flag.String("server", "", "ShadowTLS server address (required)")
	sni := flag.String("sni", "", "SNI for TLS handshake (required)")
	password := flag.String("password", "", "Shared password (required)")

	// Pool settings
	poolSize := flag.Int("pool-size", 10, "Number of pre-established connections")
	ttl := flag.Duration("ttl", 10*time.Second, "Connection TTL before refresh")
	backoff := flag.Duration("backoff", 5*time.Second, "Backoff duration on connection failure")
	timeout := flag.Duration("timeout", 10*time.Second, "Connection establishment timeout")

	// Stats settings
	statsInterval := flag.Duration("stats-interval", 10*time.Second, "Stats logging interval (0 to disable)")

	flag.Parse()

	// Initialize logging with parsed verbosity
	InitLogging(verbosity)

	if *server == "" || *sni == "" || *password == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Required:")
		fmt.Fprintln(os.Stderr, "  -server <host:port>   ShadowTLS server address")
		fmt.Fprintln(os.Stderr, "  -sni <hostname>       SNI for TLS handshake camouflage")
		fmt.Fprintln(os.Stderr, "  -password <secret>    Shared authentication password")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  -listen <addr:port>   Local listen address (default: 127.0.0.1:2222)")
		fmt.Fprintln(os.Stderr, "  -pool-size <n>        Connection pool size (default: 10)")
		fmt.Fprintln(os.Stderr, "  -ttl <duration>       Connection TTL (default: 30s)")
		fmt.Fprintln(os.Stderr, "  -backoff <duration>   Retry backoff (default: 5s)")
		fmt.Fprintln(os.Stderr, "  -timeout <duration>   Connection timeout (default: 10s)")
		fmt.Fprintln(os.Stderr, "  -stats-interval <dur> Stats logging interval (default: 10s, 0 to disable)")
		fmt.Fprintln(os.Stderr, "  -v, -vv, -vvv         Increase log verbosity (info/debug/trace)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Example:")
		fmt.Fprintln(os.Stderr, "  steady-shadowtls -server example.com:8443 -sni www.google.com -password secret")
		fmt.Fprintln(os.Stderr, "  steady-shadowtls -server example.com:8443 -sni www.google.com -password secret -vvv")
		os.Exit(1)
	}

	// Create stats tracker
	globalStats = NewStats()

	// Create ShadowTLS client
	client, err := NewShadowTLSClient(*server, *sni, *password, *timeout)
	if err != nil {
		Log.Fatalf("Failed to create ShadowTLS client: %v", err)
	}

	// Create connection factory
	factory := &ShadowTLSFactory{
		client:  client,
		timeout: *timeout,
	}

	// Create connection pool with stats
	pool := NewConnPool(*poolSize, *ttl, *backoff, factory.Create, globalStats)
	pool.Start()

	// Start listener
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		Log.Fatalf("Failed to listen on %s: %v", *listen, err)
	}

	Log.Infof("steady-shadowtls started")
	Log.Infof("  Listen: %s", *listen)
	Log.Infof("  Server: %s", *server)
	Log.Infof("  SNI: %s", *sni)
	Log.Infof("  Pool size: %d, TTL: %v, Backoff: %v", *poolSize, *ttl, *backoff)
	if *statsInterval > 0 {
		Log.Infof("  Stats interval: %v", *statsInterval)
	}

	// Handle shutdown
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// Signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGUSR1:
				// Print stats on SIGUSR1
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

	// Stats logging goroutine
	if *statsInterval > 0 {
		go func() {
			ticker := time.NewTicker(*statsInterval)
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

	// Accept loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				goto shutdown
			default:
				Log.Warnf("Accept error: %v", err)
				continue
			}
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			handleConnection(ctx, c, pool, globalStats)
		}(conn)
	}

shutdown:
	Log.Info("Waiting for connections to close...")
	wg.Wait()
	pool.Stop()

	// Print final stats
	avail, cap := pool.Stats()
	snap := globalStats.Snapshot(avail, cap)
	fmt.Println(snap.String())

	Log.Info("Shutdown complete")
}

const (
	idleTimeout  = 5 * time.Minute
	writeTimeout = 30 * time.Second
	copyBufSize  = 32 * 1024
)

// Thresholds for "significant" connections worth logging at INFO level
const (
	significantBytes    = 1024 // 1KB
	significantDuration = 5 * time.Second
)

func handleConnection(ctx context.Context, local net.Conn, pool *ConnPool, stats *Stats) {
	connStart := time.Now()
	stats.ConnStart()
	defer func() {
		stats.ConnEnd()
		stats.RecordConnLifetime(time.Since(connStart))
	}()

	defer local.Close()

	Log.Debugf("New connection from %s", local.RemoteAddr())

	// Read initial data from client so we can retry on stale pool connections.
	// The first packet is typically a SOCKS5/TLS handshake — if the tunnel is
	// dead the write fails fast, and we can replay this data on a fresh tunnel.
	initialBuf := make([]byte, copyBufSize)
	local.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, readErr := local.Read(initialBuf)
	local.SetReadDeadline(time.Time{})
	if readErr != nil || n == 0 {
		Log.Debugf("No initial data from %s: %v", local.RemoteAddr(), readErr)
		stats.ConnErrors.Add(1)
		return
	}
	initialData := initialBuf[:n]

	// Get a working tunnel, retrying on stale pool connections
	getCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	const maxRetries = 3
	var tunnel *PooledConn
	var err error
	for attempt := 0; attempt < maxRetries; attempt++ {
		tunnel, err = pool.Get(getCtx)
		if err != nil {
			break
		}

		// Write the initial data — TCP-dead connections fail here fast.
		// Note: if TCP is alive but the ShadowTLS session has timed out,
		// the write succeeds (buffered in kernel) but the server drops it.
		// The TTL check in pool.Get() handles that case.
		tunnel.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, writeErr := tunnel.Write(initialData)
		tunnel.SetWriteDeadline(time.Time{})
		if writeErr != nil {
			stats.PoolStale.Add(1)
			Log.Debugf("Stale connection discarded (attempt %d/%d): %v", attempt+1, maxRetries, writeErr)
			tunnel.Close()
			tunnel = nil
			continue
		}
		break // write succeeded
	}
	if tunnel == nil {
		if err == nil {
			err = fmt.Errorf("all pool connections stale")
		}
		Log.Warnf("Failed to get tunnel: %v", err)
		stats.ConnErrors.Add(1)
		return
	}
	defer tunnel.Close()

	if tunnel.FromPool {
		Log.Debugf("Tunnel: pooled (age=%v, rtt=%v)", tunnel.PoolAge.Round(time.Millisecond), tunnel.ConnectTime.Round(time.Millisecond))
	} else {
		Log.Debugf("Tunnel: new (rtt=%v)", tunnel.ConnectTime.Round(time.Millisecond))
	}

	// Watch for context cancellation to force-close connections
	go func() {
		<-ctx.Done()
		local.Close()
		tunnel.Close()
	}()

	// Bidirectional copy (initial data already written to tunnel)
	done := make(chan struct{}, 2)
	var bytesOut, bytesIn int64

	go func() {
		bytesOut = copyConn(tunnel, local, stats)
		tunnel.Close()
		done <- struct{}{}
	}()

	go func() {
		bytesIn = copyConn(local, tunnel, stats)
		local.Close()
		done <- struct{}{}
	}()

	// Wait for both to finish
	<-done
	<-done

	lifetime := time.Since(connStart)
	totalBytes := int64(len(initialData)) + bytesOut + bytesIn

	// Only log significant connections at INFO level
	if totalBytes >= significantBytes || lifetime >= significantDuration {
		Log.Infof("Connection closed: %s out, %s in, %v",
			formatBytesShort(int64(len(initialData))+bytesOut), formatBytesShort(bytesIn),
			lifetime.Round(time.Millisecond))
	} else {
		Log.Tracef("Connection closed: %d/%d bytes, %v",
			int64(len(initialData))+bytesOut, bytesIn, lifetime.Round(time.Millisecond))
	}
}

func formatBytesShort(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPE"[exp])
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
