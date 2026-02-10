# ShadowTLS Tunnel
A standalone [ShadowTLS](https://github.com/ihciah/shadow-tls) tunnel implementation in Go.

This project provides a single-binary, config-free tunnel that leverages [sing-shadowtls](https://github.com/metacubex/sing-shadowtls) under the hood. It is intentionally decoupled from complex proxy platforms like sing-box, Xray, or Clash, offering a lightweight entry point to the "certificate stealing" technique without the overhead of a full anti-censorship stack.

## Project Overview

**ShadowTLS** disguises arbitrary TCP traffic as legitimate HTTPS traffic. It performs a real TLS handshake with a trusted "camouflage" server (e.g., `www.google.com`) before hijacking the connection to tunnel your payload.

This technique is designed to evade active probing and Deep Packet Inspection (DPI) systems, such as the Great Firewall (GFW). By presenting a valid TLS handshake and a trusted certificate to any middlebox, the traffic is mathematically indistinguishable from a standard connection to the camouflage domain.

While [XTLS Reality](https://github.com/XTLS/Xray-core) determines the current state of the art for this "certificate stealing" approach, ShadowTLS offers a distinct implementation. Both protocols successfully show a valid TLS certificate to observers, but ShadowTLS operates as a transparent wrapper, making it simpler to integrate into existing setups or use as a standalone tunnel.

### Key Features

- **Protocol**: ShadowTLS v3 (HMAC authentication embedded in TLS ClientHello SessionID).
- **Camouflage**: Uses uTLS to mimic a Chrome browser's TLS fingerprint, preventing fingerprint-based blocking.
- **Authentication**: Zero-rtt HMAC-SHA1 handshake; unauthenticated scanners are transparently relayed to the camouflage server.
- **Minimalist**: One binary, no configuration files, just CLI flags.

## Repository Structure

The project is a single Go module (`shadowtun`) that compiles into a binary with `--mode server` and `--mode client` capabilities.

- `pkg/shadowtls/`  
  Core protocol logic: TLS handshake handling via uTLS, address parsing, and the ShadowTLS client/server wrappers. It adapts the upstream `sing-shadowtls` library for standalone use.

- `pkg/socks5/`  
  A lightweight SOCKS5 server implementation (RFC 1928) used for the client-side local proxy and server-side SOCKS mode.

- `cmd/shadowtls/`  
  The main entry point.
  - **Server**: Configures the listening port, camouflage address, and forwarding behavior (SOCKS5 or port forward).
  - **Client**: Manages the local listener, connection pooling, and transparent retries for stale connections.

- `tunnel.sh`  
  A helper script to set up a system-wide VPN using `tun2socks` (Linux only).

## Usage

### Build

```bash
go build -o shadowtls ./cmd/shadowtls/
```

### Server Mode

The server listens for incoming connections. If a connection fails ShadowTLS authentication, it is transparently proxied to the handshake server (making the server behave exactly like the camouflage domain to unauthorized visitors).

**Option 1: SOCKS5 Proxy with Wildcard SNI (Recommended)**  
Allows the client to choose the camouflage domain dynamically.

```bash
./shadowtls --mode server \
  --listen :443 \
  --password "your-secure-password" \
  --wildcard-sni \
  --socks5
```

**Option 2: Port Forwarding**  
Forwards authenticated traffic to a specific local service (e.g., SSH at 127.0.0.1:22) while mimicking `www.google.com` to everyone else.

```bash
./shadowtls --mode server \
  --listen :443 \
  --password "your-secure-password" \
  --handshake www.google.com:443 \
  --forward 127.0.0.1:22
```

### Client Mode

Connects to the ShadowTLS server and exposes a local SOCKS5 proxy interface.

```bash
./shadowtls --mode client \
  --server example.com:443 \
  --sni www.google.com \
  --password "your-secure-password" \
  --listen 127.0.0.1:1080 \
  --pool-size 5 \
  -vv
```

### System-wide VPN

Requires `tun2socks` installed. Routes all system traffic through the tunnel.

```bash
sudo ./tunnel.sh -s example.com:443 -p "your-secure-password" --sni www.google.com
```

## Architecture details

### V3 Protocol Flow

1.  **Client Hello**: The client generates a TLS `ClientHello` using uTLS with a Chrome fingerprint. The `SessionID` field is crafted to contain `HMAC-SHA1(password, ClientHello)`.
2.  **Server Verification**: The server intercepts the `ClientHello`. It recomputes the HMAC.
    *   **Mismatch**: The connection is proxied to the real camouflage server (e.g., Google). The server acts as a simpler relay.
    *   **Match**: The server hijacks the connection.
3.  **Tunneling**: An XOR key is derived from the password and server random data. All subsequent traffic is encrypted with this key, effectively creating a hidden tunnel inside the established TLS session.

### connection Pooling (Client)

To minimize latency, the client maintains a pool of pre-established connections ( `ConnPool` in `pool.go`).

- **Pre-handshake**: Worker goroutines perform the handshake in the background.
- **Fast Open**: When the user makes a request, `Get()` grabs an idle connection immediately.
- **Stale Detection**: Since ShadowTLS hijacks the connection, the server cannot send "KeepAlive" packets without breaking the illusion of a standard TLS stream. The client handles this by buffering the first packet of a new request. If the write fails (indicating the server closed the connection), the client transparently retries with a fresh connection.

### Logging

We use [logrus](https://github.com/sirupsen/logrus) for structured, level-based logging.

- `-v`: **INFO** (General startup/shutdown and connection summary)
- `-vv`: **DEBUG** (Detailed connection flow)
- `-vvv`: **TRACE** (Pool worker activity and granular IO events)

## Dependencies

- **[sing-shadowtls](https://github.com/metacubex/sing-shadowtls)**: The heavy lifting for the ShadowTLS protocol.
- **[utls](https://github.com/refraction-networking/utls)**: Essential for mimicking popular browser fingerprints.
- **[sing](https://github.com/metacubex/sing)**: Common networking primitives.
- **[logrus](https://github.com/sirupsen/logrus)**: Logging infrastructure.

NB. This doesn't handle DNS... in my case my router/gateway still works as a resolver so didn't need to include any DNS handling.
