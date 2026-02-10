# ShadowTLS Tunnel

Standalone [ShadowTLS v3](https://github.com/ihciah/shadow-tls) tunnel. One binary, no config files. Uses [sing-shadowtls](https://github.com/metacubex/sing-shadowtls) under the hood without the rest of the xray/sing-box stack.

## What this does

Your client connects to your server and performs a real TLS handshake with a legitimate website — say `www.google.com`. The server relays this handshake to Google and passes the responses back. To any network observer, this looks like a normal HTTPS connection. Once the handshake completes, the server hijacks the TCP connection: instead of forwarding application data to Google, it routes your tunnel traffic through it. The connection started as a genuine TLS session with a trusted site, but now it's your proxy.

```
You                       Proxy/Firewall                   Server
 |                             |                             |
 |-- TLS ClientHello -------->|-- SNI: google.com ---------->|
 |<- TLS ServerHello ---------|<- Google's real certificate -|
 |                             |                             |
 |   (real TLS handshake,     | (looks legitimate,          |
 |    passes fingerprinting)  |  passes SNI whitelist)      |
 |                             |                             |
 |== tunnel traffic =========>|== indistinguishable ========>|
 |<= tunnel traffic ==========|<= from HTTPS ===============|
```

The client uses [uTLS](https://github.com/refraction-networking/utls) with a Chrome fingerprint so the handshake is identical to a real browser's. Authentication is embedded in the TLS SessionID via HMAC, invisible to passive observers.

## Why this exists

[ShadowTLS](https://github.com/ihciah/shadow-tls) was designed to evade the GFW. Using legitimate TLS sessions to camouflage proxy traffic is the current state of the art for circumventing Chinese internet censorship. [XTLS Reality](https://github.com/XTLS/Xray-core) is the most widely deployed approach — it has the proxy server steal and present a real site's TLS certificate, handling termination directly. ShadowTLS works differently: it relays the entire handshake to the real server and hijacks the TCP connection afterward. Different mechanisms, same goal.

This happens to be equally effective against any network that filters traffic by TLS SNI. Transparent proxies, captive portals, and restrictive ISPs all check the SNI in your ClientHello to decide if a connection is allowed. They see `www.google.com`, it matches their whitelist, and they let it through.

I built this because I wanted a lightweight certificate-stealing proxy without being tied to a full proxy framework. This is just the tunnel.

## Quick Start

```bash
go build -o shadowtls ./cmd/shadowtls/
```

**Server** — run on a VPS with `--wildcard-sni` so clients control the camouflage domain. No server-side changes needed to switch SNI:

```bash
./shadowtls --mode server \
  --listen 0.0.0.0:443 \
  --password secret \
  --wildcard-sni \
  --socks5
```

Or pin a specific handshake server:

```bash
./shadowtls --mode server \
  --listen 0.0.0.0:443 \
  --password secret \
  --handshake www.google.com:443 \
  --socks5
```

**Client** — creates a local SOCKS5 proxy. `--sni` picks the camouflage domain:

```bash
./shadowtls --mode client \
  --server your-server.com:443 \
  --sni www.google.com \
  --password secret \
  --listen 127.0.0.1:1080 \
  -vv
```

Point your browser at `socks5://127.0.0.1:1080`.

**System-wide tunnel** — routes all traffic through it via tun2socks:

```bash
sudo ./tunnel.sh -s your-server.com:443 --sni www.google.com -p secret
```

Ctrl+C to restore original routing.

## Features

- **ShadowTLS v3** with HMAC auth in the TLS ClientHello
- **Chrome TLS fingerprint** via uTLS
- **Connection pooling** with TTL-based expiry and stale connection retry
- **Wildcard SNI** — client picks the camouflage domain, no server restart needed
- **SOCKS5 proxy** or **port forwarding** (server mode)
- **Stats** — pool hit rates, RTT, throughput, connection lifetime (`SIGUSR1` or `--stats-interval`)
- **Graceful shutdown** — drains active connections on SIGINT/SIGTERM

## Usage

```
shadowtls --mode <server|client> --password <secret> [options]

Server:
  --listen <addr:port>     Listen address
  --forward <addr:port>    Forward traffic to this backend
  --socks5                 SOCKS5 proxy instead of port forward
  --handshake <host:port>  TLS camouflage server
  --wildcard-sni           Use client's SNI as handshake server

Client:
  --listen <addr:port>     Local address (default: 127.0.0.1:1080)
  --server <addr:port>     ShadowTLS server
  --sni <hostname>         Camouflage domain
  --pool-size <n>          Pool size (default: 10)
  --ttl <duration>         Connection TTL (default: 10s)
  --backoff <duration>     Retry backoff (default: 5s)
  --timeout <duration>     Connect timeout (default: 10s)
  --stats-interval <dur>   Stats interval (default: 10s, 0=off)
  -v, -vv, -vvv            Verbosity (info/debug/trace)
```

## Requirements

- Go 1.21+
- [tun2socks](https://github.com/xjasonlyu/tun2socks) (only for `tunnel.sh`)

## License

MIT
