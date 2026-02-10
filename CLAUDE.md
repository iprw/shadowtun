# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ShadowTLS tunnel implementation in Go. Disguises arbitrary TCP traffic as legitimate TLS by performing a real TLS handshake with a camouflage server while tunneling payload data. Supports protocol versions 1-3, with v3 providing per-user HMAC authentication embedded in the TLS ClientHello SessionID.

## Repository Structure

Single Go module (`shadowtls-tunnel`), one binary with `--mode server|client`:

- **`pkg/shadowtls/`** — Protocol-level code: TLS handshake (uTLS with Chrome_Auto fingerprint), address parsing, ShadowTLS client wrapper + factory, and logrus logger adapter for sing-shadowtls.
- **`pkg/socks5/`** — SOCKS5 server implementing RFC 1928 TCP CONNECT with idle/write timeouts on relay connections.
- **`cmd/shadowtls/`** — CLI tool providing `server` and `client` modes. Server supports SOCKS5 proxy and port-forwarding with graceful shutdown. Client features connection pooling, stale connection detection, stats tracking, and logrus-based logging with `-v`/`-vv`/`-vvv` verbosity.
- **`tunnel.sh`** — System VPN script using tun2socks.

The core ShadowTLS protocol is imported from upstream `github.com/metacubex/sing-shadowtls` (meta branch).

## Build & Run

```bash
# Build
go build -o shadowtls ./cmd/shadowtls/

# Run server (SOCKS5 mode, wildcard SNI — client controls camouflage domain)
./shadowtls --mode server --listen :443 --password secret --wildcard-sni --socks5

# Run server (SOCKS5 mode, pinned handshake server)
./shadowtls --mode server --listen :443 --password secret --handshake www.google.com:443 --socks5

# Run server (port-forward mode)
./shadowtls --mode server --listen :443 --password secret --handshake www.google.com:443 --forward localhost:22

# Run client (with connection pooling)
./shadowtls --mode client --server host:443 --sni www.google.com --password secret --listen 127.0.0.1:1080 --pool-size 5 -vvv

# Run as system VPN (requires root, uses tun2socks)
sudo ./tunnel.sh -s host:443 -p secret --sni www.google.com
```

## Architecture

### V3 Protocol Flow (primary version used)

**Client side:** Generate ClientHello with `SessionID = [random(28) || HMAC-SHA1(password, clientHello)[:4]]` using uTLS (`Chrome_Auto` fingerprint). Server authenticates by recomputing the HMAC. After handshake, derive XOR key from `SHA256(password || serverRandom)` for stream encryption.

**Server side:** Extract ClientHello, verify HMAC in SessionID against configured users, relay handshake to upstream TLS server, then XOR-encrypt application data frames with HMAC verification.

### Connection Pooling (client mode)

`ConnPool` in `pool.go` runs N worker goroutines that pre-establish ShadowTLS connections. `Get()` returns a pooled connection if within TTL (default 10s), otherwise discards it and tries the next. No read-probe is used — ShadowTLS `verifiedConn` uses framed records, and partial reads corrupt the stream state. If the pool is empty, a connection is created on-demand.

`handleConnection` in `client.go` buffers the client's first packet and writes it to the tunnel as a liveness test. If the write fails (TCP-dead connection), it retries with the next pool connection (up to 3 attempts), replaying the buffered data. This handles connections that died at TCP level before TTL expired.

Stats in `stats.go` track hit rates, RTT, lifetime, pool age, stale connections, and throughput with atomic operations.

### SOCKS5 (server mode)

`pkg/socks5/socks5.go` implements RFC 1928 TCP CONNECT with optional username/password auth. UDP ASSOCIATE is rejected (ShadowTLS is TCP-only). Relay uses `copyConn` with idle timeout (5min) and write timeout (30s) to prevent ghost connections. The server can run in either port-forward or SOCKS5 mode.

### Graceful Shutdown

Both server and client handle SIGINT/SIGTERM: cancel the accept loop, wait for active connections to drain via WaitGroup, then exit. Server relay and SOCKS5 relay connections have idle/write timeouts so they don't hang indefinitely.

## Logging Convention

Uses logrus throughout. Verbosity levels: `-v` = INFO, `-vv` = DEBUG, `-vvv` = TRACE. The `-v` flags are parsed before `flag.Parse()` and removed from `os.Args`. The `ShadowTLSLogger` adapter in `pkg/shadowtls/logger.go` bridges sing-shadowtls's logger interface to logrus.

All connection closures are logged at INFO level. Pool worker messages: "connection pooled" at TRACE, connection failures at WARN.

## Gotchas

- **No read-probes on pooled connections.** ShadowTLS wraps connections in `verifiedConn` with internal framing. Any `Read()` call — even 1 byte with a short deadline — triggers frame processing. If it times out mid-frame, the internal buffer state is corrupted and all subsequent data is garbled. Only use TTL-based expiry.
- **Handshake server idle timeout.** The camouflage TLS session (e.g. to `my3.three.co.uk`) expires after ~10-15s of idle. Pool TTL must be shorter than this or connections silently die (TCP stays open but ShadowTLS session is dead). Default TTL is 10s for this reason.
- **`tunnel.sh` provides internet.** The script routes all system traffic through tun2socks. Killing it drops connectivity. The cleanup handler restores routes and iptables rules.
- **UDP causes connection loops through tun2socks.** ShadowTLS is TCP-only. Without the iptables rule in `tunnel.sh` that drops UDP on the TUN interface, UDP packets (DNS to external resolvers, QUIC) loop through tun2socks → SOCKS5 → ShadowTLS → timeout → retry, creating zombie connections. DNS is handled by the local router instead; QUIC/HTTP3 falls back to TCP automatically.

## Key Dependencies

- `github.com/metacubex/sing-shadowtls` — Core ShadowTLS v1/v2/v3 protocol (upstream, meta branch)
- `github.com/metacubex/sing` — Networking primitives, metadata types, buffer pool
- `github.com/refraction-networking/utls` — TLS fingerprint camouflage (Chrome_Auto)
- `github.com/sirupsen/logrus` — Structured logging with level control
