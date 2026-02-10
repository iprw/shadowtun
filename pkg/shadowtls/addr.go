package shadowtls

import (
	"net"
	"net/netip"
	"strconv"

	M "github.com/metacubex/sing/common/metadata"
)

// ParseHostPort splits an address into host and port.
// If no port is present, defaults to 443.
func ParseHostPort(addr string) (string, uint16) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 443
	}
	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return host, 443
	}
	return host, uint16(portNum)
}

// MakeSocksaddr creates a sing Socksaddr from host and port.
func MakeSocksaddr(host string, port uint16) M.Socksaddr {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return M.SocksaddrFromNetIP(netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip4)), port))
		}
		return M.SocksaddrFromNetIP(netip.AddrPortFrom(netip.AddrFrom16([16]byte(ip.To16())), port))
	}
	return M.Socksaddr{
		Fqdn: host,
		Port: port,
	}
}
