package main

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnPool maintains a pool of pre-established connections
type ConnPool struct {
	size    int
	ttl     time.Duration
	backoff time.Duration
	factory func(ctx context.Context) (net.Conn, error)

	connections chan *pooledConn
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	stopped     atomic.Bool

	stats *Stats
}

type pooledConn struct {
	net.Conn
	createdAt   time.Time
	connectTime time.Duration // How long it took to establish
}

// NewConnPool creates a new connection pool
func NewConnPool(size int, ttl, backoff time.Duration, factory func(ctx context.Context) (net.Conn, error), stats *Stats) *ConnPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &ConnPool{
		size:        size,
		ttl:         ttl,
		backoff:     backoff,
		factory:     factory,
		connections: make(chan *pooledConn, size),
		ctx:         ctx,
		cancel:      cancel,
		stats:       stats,
	}
}

// Start begins the pool workers
func (p *ConnPool) Start() {
	for i := 0; i < p.size; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}
}

// Stop gracefully shuts down the pool
func (p *ConnPool) Stop() {
	p.stopped.Store(true)
	p.cancel()

	// Wait for workers with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Workers finished
	case <-time.After(5 * time.Second):
		Log.Warn("Pool shutdown timed out, forcing close")
	}

	// Drain remaining connections
	for {
		select {
		case pc := <-p.connections:
			if pc != nil {
				pc.Conn.Close()
			}
		default:
			goto drained
		}
	}
drained:
}

// Stats returns pool statistics
func (p *ConnPool) Stats() (available int, capacity int) {
	return len(p.connections), p.size
}

// worker maintains one connection slot in the pool
func (p *ConnPool) worker(id int) {
	defer p.wg.Done()

	for {
		// Check for shutdown
		if p.stopped.Load() || p.ctx.Err() != nil {
			return
		}

		// Create connection with timeout derived from pool context
		connCtx, connCancel := context.WithTimeout(p.ctx, 30*time.Second)
		start := time.Now()
		conn, err := p.factory(connCtx)
		connectTime := time.Since(start)
		connCancel()

		if err != nil {
			if p.stopped.Load() || p.ctx.Err() != nil {
				return // Shutting down
			}
			p.stats.PoolFailed.Add(1)
			Log.Warnf("Pool connect failed: %v", err)
			// Backoff before retry
			select {
			case <-time.After(p.backoff):
			case <-p.ctx.Done():
				return
			}
			continue
		}

		p.stats.PoolCreated.Add(1)
		p.stats.RecordConnectTime(connectTime)

		pc := &pooledConn{
			Conn:        conn,
			createdAt:   time.Now(),
			connectTime: connectTime,
		}

		// Try to add to pool with timeout
		select {
		case p.connections <- pc:
			Log.Tracef("Worker %d: connection pooled", id)
			// Successfully added, loop to create next connection
			// The connection will be cleaned up by Get() or Stop()

		case <-time.After(p.ttl):
			// Pool is full and stayed full, discard this connection
			p.stats.PoolDiscarded.Add(1)
			conn.Close()

		case <-p.ctx.Done():
			conn.Close()
			return
		}
	}
}

// PooledConn wraps a connection with metadata
type PooledConn struct {
	net.Conn
	PoolAge     time.Duration // How long it sat in the pool
	ConnectTime time.Duration // How long it took to establish
	FromPool    bool          // True if from pool, false if newly created
}

// Get retrieves a connection from the pool.
// Only checks TTL expiry — no read-probe, since ShadowTLS uses framed
// records and a partial read would corrupt the stream.
func (p *ConnPool) Get(ctx context.Context) (*PooledConn, error) {
	waitStart := time.Now()

	// Try to get from pool first, discarding expired connections
	for {
		select {
		case pc := <-p.connections:
			poolAge := time.Since(pc.createdAt)

			if poolAge <= p.ttl {
				p.stats.PoolHits.Add(1)
				p.stats.RecordPoolAge(poolAge)
				p.stats.RecordPoolWait(time.Since(waitStart))
				return &PooledConn{
					Conn:        pc.Conn,
					PoolAge:     poolAge,
					ConnectTime: pc.connectTime,
					FromPool:    true,
				}, nil
			}
			// Connection expired, close and try next
			p.stats.PoolExpired.Add(1)
			pc.Conn.Close()
			continue

		case <-ctx.Done():
			return nil, ctx.Err()

		default:
			// Pool empty, create new connection with context
			p.stats.PoolMisses.Add(1)
			start := time.Now()
			conn, err := p.factory(ctx)
			if err != nil {
				return nil, err
			}
			connectTime := time.Since(start)
			p.stats.RecordConnectTime(connectTime)
			p.stats.RecordPoolWait(time.Since(waitStart))
			return &PooledConn{
				Conn:        conn,
				PoolAge:     0,
				ConnectTime: connectTime,
				FromPool:    false,
			}, nil
		}
	}
}
