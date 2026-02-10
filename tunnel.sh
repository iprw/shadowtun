#!/bin/bash
#
# tunnel.sh - Set up a full system tunnel using tun2socks + shadowtls
#
# This script:
# 1. Starts shadowtls SOCKS5 client
# 2. Creates a TUN interface
# 3. Routes traffic through tun2socks
# 4. Excludes the server IP to prevent routing loops
#

set -e

# Configuration - modify these or pass as arguments
SERVER="${SERVER:-}"
SNI="${SNI:-}"
PASSWORD="${PASSWORD:-}"
LISTEN_PORT="${LISTEN_PORT:-1080}"
POOL_SIZE="${POOL_SIZE:-2}"
TUN_NAME="${TUN_NAME:-tun0}"
TUN_ADDR="${TUN_ADDR:-10.0.85.1}"
TUN_GW="${TUN_GW:-10.0.85.2}"
TUN_MASK="${TUN_MASK:-255.255.255.0}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--server)
            SERVER="$2"
            shift 2
            ;;
        --sni)
            SNI="$2"
            shift 2
            ;;
        -p|--password)
            PASSWORD="$2"
            shift 2
            ;;
        --port)
            LISTEN_PORT="$2"
            shift 2
            ;;
        --pool)
            POOL_SIZE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Required:"
            echo "  -s, --server HOST:PORT    ShadowTLS server address"
            echo "  --sni HOSTNAME            SNI for TLS handshake"
            echo "  -p, --password SECRET     Shared password"
            echo ""
            echo "Optional:"
            echo "  --port PORT               Local SOCKS5 port (default: 1080)"
            echo "  --pool SIZE               Connection pool size (default: 5)"
            echo ""
            echo "Example:"
            echo "  sudo $0 -s example.com:443 --sni www.google.com -p secret123"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate required arguments
if [[ -z "$SERVER" || -z "$SNI" || -z "$PASSWORD" ]]; then
    echo "Error: Missing required arguments"
    echo "Run '$0 --help' for usage"
    exit 1
fi

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHADOWTLS_BIN="$SCRIPT_DIR/shadowtls"

# Check for required binaries
if [[ ! -x "$SHADOWTLS_BIN" ]]; then
    echo "Error: shadowtls not found at $SHADOWTLS_BIN"
    echo "Run: cd $SCRIPT_DIR && go build -o shadowtls ./cmd/shadowtls/"
    exit 1
fi

if ! command -v tun2socks &> /dev/null; then
    echo "Error: tun2socks not found"
    echo "Install with: go install github.com/xjasonlyu/tun2socks/v2@latest"
    echo "Or download from: https://github.com/xjasonlyu/tun2socks/releases"
    exit 1
fi

# Extract server host (without port) for route exclusion
SERVER_HOST="${SERVER%%:*}"

# Resolve hostname to IP if needed
if [[ ! "$SERVER_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Resolving $SERVER_HOST..."
    SERVER_IP=$(dig +short "$SERVER_HOST" | head -1)
    if [[ -z "$SERVER_IP" ]]; then
        echo "Error: Could not resolve $SERVER_HOST"
        exit 1
    fi
    echo "Resolved to: $SERVER_IP"
else
    SERVER_IP="$SERVER_HOST"
fi

# Get default gateway and interface
DEFAULT_GW=$(ip route | grep '^default' | awk '{print $3}' | head -1)
DEFAULT_IF=$(ip route | grep '^default' | awk '{print $5}' | head -1)

if [[ -z "$DEFAULT_GW" || -z "$DEFAULT_IF" ]]; then
    echo "Error: Could not determine default gateway"
    exit 1
fi

echo "Default gateway: $DEFAULT_GW via $DEFAULT_IF"

# DNS server (auto-detect from current resolv.conf, fallback to gateway)
if [[ -z "$DNS_SERVER" ]]; then
    DNS_SERVER=$(grep -m1 '^nameserver' /etc/resolv.conf | awk '{print $2}')
    DNS_SERVER="${DNS_SERVER:-$DEFAULT_GW}"
fi

# Store original DNS
ORIG_RESOLV=$(cat /etc/resolv.conf)

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."

    # Kill our processes
    [[ -n "$TUN2SOCKS_PID" ]] && kill $TUN2SOCKS_PID 2>/dev/null || true
    [[ -n "$SHADOWTLS_PID" ]] && kill $SHADOWTLS_PID 2>/dev/null || true

    # Wait for processes to exit
    sleep 2

    # Remove TUN default route
    ip route del default dev "$TUN_NAME" 2>/dev/null || true

    # Remove backup default route
    ip route del default via "$DEFAULT_GW" metric 100 2>/dev/null || true

    # Restore original default route
    ip route add default via "$DEFAULT_GW" dev "$DEFAULT_IF" 2>/dev/null || true

    # Remove bypass routes
    ip route del "$SERVER_IP/32" via "$DEFAULT_GW" dev "$DEFAULT_IF" 2>/dev/null || true

    # Remove UDP block on TUN
    iptables -D OUTPUT -o "$TUN_NAME" -p udp -j DROP 2>/dev/null || true

    # Delete TUN interface
    ip link del "$TUN_NAME" 2>/dev/null || true

    # Restore DNS
    echo "$ORIG_RESOLV" > /etc/resolv.conf

    echo "Cleanup complete"
}

trap cleanup EXIT INT TERM

echo ""
echo "=== Starting ShadowTLS Tunnel ==="
echo "Server: $SERVER ($SERVER_IP)"
echo "SNI: $SNI"
echo "Local SOCKS5: 127.0.0.1:$LISTEN_PORT"
echo "TUN interface: $TUN_NAME ($TUN_ADDR)"
echo ""

# Step 1: Add bypass route for server (prevent routing loop)
echo "[1/5] Adding bypass route for server..."
echo "      Server: $SERVER_IP"
ip route add "$SERVER_IP/32" via "$DEFAULT_GW" dev "$DEFAULT_IF" 2>/dev/null || \
    echo "      (route may already exist)"
echo "      DNS: $DNS_SERVER (local, no bypass needed)"

# Step 2: Start shadowtls client
echo "[2/5] Starting shadowtls client..."
"$SHADOWTLS_BIN" \
    --mode client \
    --listen "127.0.0.1:$LISTEN_PORT" \
    --server "$SERVER" \
    --timeout 30s \
    --sni "$SNI" \
    --ttl 10s \
    --password "$PASSWORD" \
    --pool-size "$POOL_SIZE" \
    -vvv &
SHADOWTLS_PID=$!

# Wait for it to start
sleep 2

# Check if it's running
if ! kill -0 $SHADOWTLS_PID 2>/dev/null; then
    echo "Error: shadowtls failed to start"
    exit 1
fi
echo "      PID: $SHADOWTLS_PID"

# Step 3: Create TUN interface
echo "[3/5] Creating TUN interface..."
ip tuntap add mode tun dev "$TUN_NAME" 2>/dev/null || true
ip addr add "$TUN_ADDR/24" dev "$TUN_NAME" 2>/dev/null || true
ip link set "$TUN_NAME" up

# Step 4: Start tun2socks
echo "[4/5] Starting tun2socks..."
# TCP-only: UDP is not tunneled (DNS uses local router, QUIC falls back to TCP)
tun2socks -device "tun://$TUN_NAME" -proxy "socks5://127.0.0.1:$LISTEN_PORT" -loglevel debug &
TUN2SOCKS_PID=$!
echo "      PID: $TUN2SOCKS_PID"

# Step 5: Set up routing
echo "[5/5] Setting up routes..."

# Block UDP on TUN — ShadowTLS is TCP-only, UDP cannot traverse it.
# Without this rule, UDP packets (DNS, QUIC) create a loop:
#   app → tun0 → tun2socks → SOCKS5 → ShadowTLS → timeout → retry
# DNS uses local router instead. QUIC/HTTP3 falls back to TCP automatically.
iptables -C OUTPUT -o "$TUN_NAME" -p udp -j DROP 2>/dev/null || \
    iptables -A OUTPUT -o "$TUN_NAME" -p udp -j DROP

# Delete existing default route and add new one via TUN
ip route del default 2>/dev/null || true
ip route add default via "$DEFAULT_GW" dev "$DEFAULT_IF" metric 100
ip route add default dev "$TUN_NAME" metric 1

# Re-add server bypass route to ensure it takes precedence
ip route replace "$SERVER_IP/32" via "$DEFAULT_GW" dev "$DEFAULT_IF"

# Set up DNS (use local router)
cat > /etc/resolv.conf << EOF
nameserver $DNS_SERVER
EOF

# Verify DNS is working
echo "      Testing DNS ($DNS_SERVER)..."
if host google.com "$DNS_SERVER" >/dev/null 2>&1 || dig google.com @"$DNS_SERVER" +short >/dev/null 2>&1; then
    echo "      DNS OK"
else
    echo "      WARNING: DNS test failed"
fi

echo ""
echo "=== Tunnel Active ==="
echo ""
echo "All traffic is now routed through the tunnel."
echo "Bypassed: Server ($SERVER_IP)"
echo "DNS: $DNS_SERVER (local)"
echo ""
echo "Testing connection..."
if curl -s --max-time 10 https://httpbin.org/ip 2>/dev/null; then
    echo ""
    echo "Tunnel is working!"
else
    echo "Warning: Test request failed. Check connectivity."
fi
echo ""
echo "Press Ctrl+C to stop the tunnel"
echo ""

# Wait for processes
wait $SHADOWTLS_PID $TUN2SOCKS_PID
