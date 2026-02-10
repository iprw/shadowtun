package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// atomicMin updates a to min(a, v) atomically.
func atomicMin(a *atomic.Int64, v int64) {
	for {
		old := a.Load()
		if v >= old || a.CompareAndSwap(old, v) {
			return
		}
	}
}

// atomicMax updates a to max(a, v) atomically.
func atomicMax(a *atomic.Int64, v int64) {
	for {
		old := a.Load()
		if v <= old || a.CompareAndSwap(old, v) {
			return
		}
	}
}

// Stats tracks performance metrics for the tunnel
type Stats struct {
	// Pool stats
	PoolCreated   atomic.Uint64 // Connections created by pool workers
	PoolExpired   atomic.Uint64 // Connections expired (TTL) when retrieved from pool
	PoolFailed    atomic.Uint64 // Connection creation failures
	PoolDiscarded atomic.Uint64 // Connections discarded by workers (pool full for TTL duration)
	PoolStale     atomic.Uint64 // Connections that failed write/read verification
	PoolWaitTime  atomic.Int64  // Total time spent waiting for pool (nanoseconds)
	PoolWaitCount atomic.Uint64 // Number of pool waits
	PoolHits      atomic.Uint64 // Got connection from pool
	PoolMisses    atomic.Uint64 // Had to create new connection (pool empty)

	// Connection stats
	ActiveConns atomic.Int64  // Currently active connections
	TotalConns  atomic.Uint64 // Total connections handled
	TotalBytes  atomic.Uint64 // Total bytes transferred
	ConnErrors  atomic.Uint64 // Connection errors during relay

	// Timing stats (stored as nanoseconds)
	ConnectTimeTotal atomic.Int64  // Total connection establishment time
	ConnectTimeCount atomic.Uint64 // Number of connection time samples
	ConnectTimeMin   atomic.Int64  // Minimum connect time
	ConnectTimeMax   atomic.Int64  // Maximum connect time

	// Connection lifetime tracking
	ConnLifetimeTotal atomic.Int64  // Total connection lifetime
	ConnLifetimeCount atomic.Uint64 // Number of lifetime samples
	ConnLifetimeMin   atomic.Int64  // Minimum lifetime
	ConnLifetimeMax   atomic.Int64  // Maximum lifetime

	// Pool age tracking (time connection spent in pool before use)
	PoolAgeTotal atomic.Int64  // Total pool age
	PoolAgeCount atomic.Uint64 // Number of pool age samples
	PoolAgeMin   atomic.Int64  // Minimum pool age
	PoolAgeMax   atomic.Int64  // Maximum pool age

	// Start time
	startTime time.Time

	// For peak tracking
	peakActiveConns atomic.Int64
}

// NewStats creates a new stats tracker
func NewStats() *Stats {
	s := &Stats{
		startTime: time.Now(),
	}
	// Initialize min values to max int64
	s.ConnectTimeMin.Store(int64(^uint64(0) >> 1))
	s.ConnLifetimeMin.Store(int64(^uint64(0) >> 1))
	s.PoolAgeMin.Store(int64(^uint64(0) >> 1))
	return s
}

// RecordConnectTime records a connection establishment time
func (s *Stats) RecordConnectTime(d time.Duration) {
	ns := d.Nanoseconds()
	s.ConnectTimeTotal.Add(ns)
	s.ConnectTimeCount.Add(1)
	atomicMin(&s.ConnectTimeMin, ns)
	atomicMax(&s.ConnectTimeMax, ns)
}

// RecordConnLifetime records how long a connection was used
func (s *Stats) RecordConnLifetime(d time.Duration) {
	ns := d.Nanoseconds()
	s.ConnLifetimeTotal.Add(ns)
	s.ConnLifetimeCount.Add(1)
	atomicMin(&s.ConnLifetimeMin, ns)
	atomicMax(&s.ConnLifetimeMax, ns)
}

// RecordPoolAge records how long a connection sat in the pool before use
func (s *Stats) RecordPoolAge(d time.Duration) {
	ns := d.Nanoseconds()
	s.PoolAgeTotal.Add(ns)
	s.PoolAgeCount.Add(1)
	atomicMin(&s.PoolAgeMin, ns)
	atomicMax(&s.PoolAgeMax, ns)
}

// RecordPoolWait records time spent waiting for a connection from the pool
func (s *Stats) RecordPoolWait(d time.Duration) {
	s.PoolWaitTime.Add(d.Nanoseconds())
	s.PoolWaitCount.Add(1)
}

// ConnStart marks a connection as started
func (s *Stats) ConnStart() {
	s.TotalConns.Add(1)
	active := s.ActiveConns.Add(1)
	atomicMax(&s.peakActiveConns, active)
}

// ConnEnd marks a connection as ended
func (s *Stats) ConnEnd() {
	s.ActiveConns.Add(-1)
}

// AddBytes adds to the byte counter
func (s *Stats) AddBytes(n uint64) {
	s.TotalBytes.Add(n)
}

// StatsSnapshot is a point-in-time snapshot of stats
type StatsSnapshot struct {
	Uptime time.Duration

	// Pool
	PoolSize      int
	PoolAvailable int
	PoolCreated   uint64
	PoolExpired   uint64
	PoolFailed    uint64
	PoolDiscarded uint64
	PoolStale     uint64
	PoolHits      uint64
	PoolMisses    uint64
	PoolHitRate   float64
	PoolAvgWait   time.Duration

	// Connections
	ActiveConns int64
	PeakConns   int64
	TotalConns  uint64
	TotalBytes  uint64
	ConnErrors  uint64

	// Connection timing
	AvgConnectTime time.Duration
	MinConnectTime time.Duration
	MaxConnectTime time.Duration

	// Connection lifetime
	AvgConnLifetime time.Duration
	MinConnLifetime time.Duration
	MaxConnLifetime time.Duration

	// Pool age (freshness)
	AvgPoolAge time.Duration
	MinPoolAge time.Duration
	MaxPoolAge time.Duration
}

// Snapshot creates a stats snapshot
func (s *Stats) Snapshot(poolAvail, poolSize int) StatsSnapshot {
	snap := StatsSnapshot{
		Uptime:        time.Since(s.startTime),
		PoolSize:      poolSize,
		PoolAvailable: poolAvail,
		PoolCreated:   s.PoolCreated.Load(),
		PoolExpired:   s.PoolExpired.Load(),
		PoolFailed:    s.PoolFailed.Load(),
		PoolDiscarded: s.PoolDiscarded.Load(),
		PoolStale:     s.PoolStale.Load(),
		PoolHits:      s.PoolHits.Load(),
		PoolMisses:    s.PoolMisses.Load(),
		ActiveConns:   s.ActiveConns.Load(),
		PeakConns:     s.peakActiveConns.Load(),
		TotalConns:    s.TotalConns.Load(),
		TotalBytes:    s.TotalBytes.Load(),
		ConnErrors:    s.ConnErrors.Load(),
	}

	// Calculate hit rate
	total := snap.PoolHits + snap.PoolMisses
	if total > 0 {
		snap.PoolHitRate = float64(snap.PoolHits) / float64(total) * 100
	}

	// Calculate averages
	if count := s.PoolWaitCount.Load(); count > 0 {
		snap.PoolAvgWait = time.Duration(s.PoolWaitTime.Load() / int64(count))
	}

	if count := s.ConnectTimeCount.Load(); count > 0 {
		snap.AvgConnectTime = time.Duration(s.ConnectTimeTotal.Load() / int64(count))
		snap.MinConnectTime = time.Duration(s.ConnectTimeMin.Load())
		snap.MaxConnectTime = time.Duration(s.ConnectTimeMax.Load())
	}

	if count := s.ConnLifetimeCount.Load(); count > 0 {
		snap.AvgConnLifetime = time.Duration(s.ConnLifetimeTotal.Load() / int64(count))
		snap.MinConnLifetime = time.Duration(s.ConnLifetimeMin.Load())
		snap.MaxConnLifetime = time.Duration(s.ConnLifetimeMax.Load())
	}

	if count := s.PoolAgeCount.Load(); count > 0 {
		snap.AvgPoolAge = time.Duration(s.PoolAgeTotal.Load() / int64(count))
		snap.MinPoolAge = time.Duration(s.PoolAgeMin.Load())
		snap.MaxPoolAge = time.Duration(s.PoolAgeMax.Load())
	}

	return snap
}

// String formats the snapshot for display
func (snap StatsSnapshot) String() string {
	rttStr := "n/a"
	if snap.AvgConnectTime > 0 {
		rttStr = fmt.Sprintf("avg=%v min=%v max=%v",
			snap.AvgConnectTime.Round(time.Millisecond),
			snap.MinConnectTime.Round(time.Millisecond),
			snap.MaxConnectTime.Round(time.Millisecond))
	}

	lifetimeStr := "n/a"
	if snap.AvgConnLifetime > 0 {
		lifetimeStr = fmt.Sprintf("avg=%v min=%v max=%v",
			snap.AvgConnLifetime.Round(time.Millisecond),
			snap.MinConnLifetime.Round(time.Millisecond),
			snap.MaxConnLifetime.Round(time.Millisecond))
	}

	poolAgeStr := "n/a"
	if snap.AvgPoolAge > 0 {
		poolAgeStr = fmt.Sprintf("avg=%v min=%v max=%v",
			snap.AvgPoolAge.Round(time.Millisecond),
			snap.MinPoolAge.Round(time.Millisecond),
			snap.MaxPoolAge.Round(time.Millisecond))
	}

	return fmt.Sprintf(`
=== Tunnel Statistics ===
Uptime: %v

Pool:
  Size: %d, Available: %d
  Created: %d, Reused: %d (%.1f%% hit rate)
  Expired: %d, Failed: %d, Discarded: %d, Stale: %d
  Avg wait: %v

Connections:
  Active: %d, Peak: %d, Total: %d
  Errors: %d
  Bytes transferred: %s

Timing:
  Connect RTT:   %s
  Conn lifetime: %s
  Pool age:      %s
`,
		snap.Uptime.Round(time.Second),
		snap.PoolSize, snap.PoolAvailable,
		snap.PoolCreated, snap.PoolHits, snap.PoolHitRate,
		snap.PoolExpired, snap.PoolFailed, snap.PoolDiscarded, snap.PoolStale,
		snap.PoolAvgWait.Round(time.Millisecond),
		snap.ActiveConns, snap.PeakConns, snap.TotalConns,
		snap.ConnErrors,
		formatBytes(snap.TotalBytes, false),
		rttStr,
		lifetimeStr,
		poolAgeStr,
	)
}

// Log prints a condensed stats line
func (snap StatsSnapshot) Log() {
	// Throughput rate
	var rate string
	if snap.Uptime > 0 {
		bps := float64(snap.TotalBytes) / snap.Uptime.Seconds()
		if bps >= 1024 {
			rate = formatBytes(uint64(bps), false) + "/s"
		} else {
			rate = fmt.Sprintf("%dB/s", uint64(bps))
		}
	}

	// Only show non-zero problem counters
	var problems string
	parts := make([]string, 0, 3)
	if snap.ConnErrors > 0 {
		parts = append(parts, fmt.Sprintf("err=%d", snap.ConnErrors))
	}
	if snap.PoolStale > 0 {
		parts = append(parts, fmt.Sprintf("stale=%d", snap.PoolStale))
	}
	if snap.PoolFailed > 0 {
		parts = append(parts, fmt.Sprintf("fail=%d", snap.PoolFailed))
	}
	if len(parts) > 0 {
		problems = " [" + strings.Join(parts, " ") + "]"
	}

	Log.Infof("[STATS] active=%d peak=%d total=%d pool=%d/%d hit=%.0f%% rtt=%v life=%v age=%v bytes=%s (%s)%s",
		snap.ActiveConns, snap.PeakConns, snap.TotalConns,
		snap.PoolAvailable, snap.PoolSize,
		snap.PoolHitRate,
		snap.AvgConnectTime.Round(time.Millisecond),
		snap.AvgConnLifetime.Round(time.Millisecond),
		snap.AvgPoolAge.Round(time.Millisecond),
		formatBytes(snap.TotalBytes, false), rate,
		problems,
	)
}

func formatBytes(b uint64, short bool) string {
	const unit = 1024
	if b < unit {
		if short {
			return fmt.Sprintf("%dB", b)
		}
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	if short {
		return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPE"[exp])
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
