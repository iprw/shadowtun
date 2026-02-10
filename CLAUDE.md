# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ShadowTLS tunnel implementation in Go. Disguises arbitrary TCP traffic as legitimate TLS by performing a real TLS handshake with a camouflage server while tunneling payload data. Supports protocol versions 1-3, with v3 providing per-user HMAC authentication embedded in the TLS ClientHello SessionID.

## Repository Structure

Two Go modules, plus a shared package:

- **`pkg/shadowtls/`** — Shared code used by both binaries: TLS handshake function (uTLS with Chrome_Auto fingerprint) and address parsing utilities.
- **`cmd/shadowtls/`** — CLI tool providing `server` and `client` subcommands with SOCKS5 proxy support (TCP CONNECT only). Part of the root `shadowtls-tunnel` module.
- **`steady-shadowtls/`** — Separate module. Connection-pooling client wrapper. Pre-establishes ShadowTLS connections for lower latency. Includes stats tracking, logrus-based logging with `-v`/`-vv`/`-vvv` verbosity, and `tunnel.sh` for full system VPN via tun2socks.

The core ShadowTLS protocol is imported from upstream `github.com/metacubex/sing-shadowtls` (meta branch). `steady-shadowtls/go.mod` uses a `replace` directive to import the root module's shared package.

## Build & Run

```bash
# Build
go build -o shadowtls ./cmd/shadowtls/
cd steady-shadowtls && go build -o steady-shadowtls .

# Run server (SOCKS5 mode)
./shadowtls server -listen :443 -password secret -handshake www.google.com:443 -socks5

# Run basic client
./shadowtls client -server host:443 -sni www.google.com -password secret -listen 127.0.0.1:1080

# Run pooling client
./steady-shadowtls -server host:443 -sni www.google.com -password secret -listen 127.0.0.1:1080 -pool-size 5 -vvv

# Run as system VPN (requires root, uses tun2socks)
cd steady-shadowtls && sudo ./tunnel.sh -s host:443 -p secret --sni www.google.com
```

## Architecture

### V3 Protocol Flow (primary version used)

**Client side:** Generate ClientHello with `SessionID = [random(28) || HMAC-SHA1(password, clientHello)[:4]]` using uTLS (`Chrome_Auto` fingerprint). Server authenticates by recomputing the HMAC. After handshake, derive XOR key from `SHA256(password || serverRandom)` for stream encryption.

**Server side:** Extract ClientHello, verify HMAC in SessionID against configured users, relay handshake to upstream TLS server, then XOR-encrypt application data frames with HMAC verification.

### Connection Pooling (steady-shadowtls)

`ConnPool` in `pool.go` runs N worker goroutines that pre-establish ShadowTLS connections. `Get()` returns a pooled connection if within TTL (default 10s), otherwise discards it and tries the next. No read-probe is used — ShadowTLS `verifiedConn` uses framed records, and partial reads corrupt the stream state. If the pool is empty, a connection is created on-demand.

`handleConnection` in `main.go` buffers the client's first packet and writes it to the tunnel as a liveness test. If the write fails (TCP-dead connection), it retries with the next pool connection (up to 3 attempts), replaying the buffered data. This handles connections that died at TCP level before TTL expired.

Stats in `stats.go` track hit rates, RTT, lifetime, pool age, stale connections, and throughput with atomic operations.

### SOCKS5 (cmd/shadowtls)

`socks5.go` implements RFC 1928 TCP CONNECT. UDP ASSOCIATE is rejected (ShadowTLS is TCP-only). The server can run in either port-forward or SOCKS5 mode.

## Logging Convention (steady-shadowtls)

Uses logrus. Verbosity levels: `-v` = INFO, `-vv` = DEBUG, `-vvv` = TRACE. The `-v` flags are parsed before `flag.Parse()` and removed from `os.Args`. The `ShadowTLSLogger` adapter bridges sing-shadowtls's logger interface to logrus.

Trivial connections (< 1KB, < 5s) are logged at TRACE level; significant ones at INFO. Pool worker messages: "connection pooled" at TRACE, connection failures at WARN.

## Gotchas

- **No read-probes on pooled connections.** ShadowTLS wraps connections in `verifiedConn` with internal framing. Any `Read()` call — even 1 byte with a short deadline — triggers frame processing. If it times out mid-frame, the internal buffer state is corrupted and all subsequent data is garbled. Only use TTL-based expiry.
- **Handshake server idle timeout.** The camouflage TLS session (e.g. to `my3.three.co.uk`) expires after ~10-15s of idle. Pool TTL must be shorter than this or connections silently die (TCP stays open but ShadowTLS session is dead). Default TTL is 10s for this reason.
- **`tunnel.sh` provides internet.** The script routes all system traffic through tun2socks. Killing it drops connectivity. The cleanup handler restores routes and iptables rules.
- **UDP causes connection loops through tun2socks.** ShadowTLS is TCP-only. Without the iptables rule in `tunnel.sh` that drops UDP on the TUN interface, UDP packets (DNS to external resolvers, QUIC) loop through tun2socks → SOCKS5 → ShadowTLS → timeout → retry, creating zombie connections. DNS is handled by the local router instead; QUIC/HTTP3 falls back to TCP automatically.

## Key Dependencies

- `github.com/metacubex/sing-shadowtls` — Core ShadowTLS v1/v2/v3 protocol (upstream, meta branch)
- `github.com/metacubex/sing` — Networking primitives, metadata types, buffer pool
- `github.com/refraction-networking/utls` — TLS fingerprint camouflage (Chrome_Auto)
- `github.com/sirupsen/logrus` — Structured logging (steady-shadowtls only)
