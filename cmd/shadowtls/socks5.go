package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

const (
	socks5Version = 0x05

	// Auth methods
	authNone     = 0x00
	authPassword = 0x02
	authNoAccept = 0xFF

	// Commands
	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	// Address types
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	// Reply codes
	repSuccess          = 0x00
	repGeneralFailure   = 0x01
	repConnNotAllowed   = 0x02
	repNetworkUnreach   = 0x03
	repHostUnreach      = 0x04
	repConnRefused      = 0x05
	repTTLExpired       = 0x06
	repCmdNotSupported  = 0x07
	repAtypNotSupported = 0x08
)

// SOCKS5Handler handles SOCKS5 protocol on a connection
type SOCKS5Handler struct {
	username string
	password string
}

// NewSOCKS5Handler creates a new SOCKS5 handler
func NewSOCKS5Handler(username, password string) *SOCKS5Handler {
	return &SOCKS5Handler{
		username: username,
		password: password,
	}
}

// Handle processes a SOCKS5 connection
func (h *SOCKS5Handler) Handle(ctx context.Context, conn net.Conn) error {
	// 1. Handshake - read auth methods
	if err := h.handshake(conn); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	// 2. Read request
	cmd, target, err := h.readRequest(conn)
	if err != nil {
		return fmt.Errorf("read request failed: %w", err)
	}

	switch cmd {
	case cmdConnect:
		return h.handleConnect(conn, target)
	default:
		h.sendReply(conn, repCmdNotSupported, nil)
		return fmt.Errorf("unsupported command: %d", cmd)
	}
}

// handleConnect handles TCP CONNECT requests
func (h *SOCKS5Handler) handleConnect(conn net.Conn, target string) error {
	log.Printf("SOCKS5 CONNECT to %s", target)

	// Connect to target
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		h.sendReply(conn, repHostUnreach, nil)
		return fmt.Errorf("connect to %s failed: %w", target, err)
	}
	defer targetConn.Close()

	// Send success reply
	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	if err := h.sendReply(conn, repSuccess, localAddr); err != nil {
		return fmt.Errorf("send reply failed: %w", err)
	}

	// Relay data
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, conn)
		targetConn.(*net.TCPConn).CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, targetConn)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	return nil
}

func (h *SOCKS5Handler) handshake(conn net.Conn) error {
	// Read version and number of methods
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	// Read methods
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Check if we need auth
	needAuth := h.username != "" && h.password != ""

	if needAuth {
		// Look for username/password auth
		hasAuth := false
		for _, m := range methods {
			if m == authPassword {
				hasAuth = true
				break
			}
		}
		if !hasAuth {
			conn.Write([]byte{socks5Version, authNoAccept})
			return fmt.Errorf("client doesn't support password auth")
		}

		// Request password auth
		conn.Write([]byte{socks5Version, authPassword})

		// Read auth request
		if err := h.readAuth(conn); err != nil {
			return err
		}
	} else {
		// No auth required
		hasNoAuth := false
		for _, m := range methods {
			if m == authNone {
				hasNoAuth = true
				break
			}
		}
		if !hasNoAuth {
			conn.Write([]byte{socks5Version, authNoAccept})
			return fmt.Errorf("client doesn't support no-auth")
		}
		conn.Write([]byte{socks5Version, authNone})
	}

	return nil
}

func (h *SOCKS5Handler) readAuth(conn net.Conn) error {
	// Auth version
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return err
	}
	if version[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", version[0])
	}

	// Username
	ulen := make([]byte, 1)
	if _, err := io.ReadFull(conn, ulen); err != nil {
		return err
	}
	username := make([]byte, ulen[0])
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	// Password
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}
	password := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	// Verify
	if string(username) != h.username || string(password) != h.password {
		conn.Write([]byte{0x01, 0x01}) // Auth failed
		return fmt.Errorf("auth failed")
	}

	conn.Write([]byte{0x01, 0x00}) // Auth success
	return nil
}

func (h *SOCKS5Handler) readRequest(conn net.Conn) (cmd byte, addr string, err error) {
	// Read header: VER CMD RSV ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, "", err
	}

	if header[0] != socks5Version {
		return 0, "", fmt.Errorf("unsupported version: %d", header[0])
	}

	cmd = header[1]

	// Read address
	var host string
	switch header[3] {
	case atypIPv4:
		addrBytes := make([]byte, 4)
		if _, err := io.ReadFull(conn, addrBytes); err != nil {
			return 0, "", err
		}
		host = net.IP(addrBytes).String()

	case atypDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return 0, "", err
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return 0, "", err
		}
		host = string(domain)

	case atypIPv6:
		addrBytes := make([]byte, 16)
		if _, err := io.ReadFull(conn, addrBytes); err != nil {
			return 0, "", err
		}
		host = net.IP(addrBytes).String()

	default:
		h.sendReply(conn, repAtypNotSupported, nil)
		return 0, "", fmt.Errorf("unsupported address type: %d", header[3])
	}

	// Read port
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return 0, "", err
	}
	port := binary.BigEndian.Uint16(portBytes)

	return cmd, fmt.Sprintf("%s:%d", host, port), nil
}

func (h *SOCKS5Handler) sendReply(conn net.Conn, rep byte, addr *net.TCPAddr) error {
	reply := []byte{socks5Version, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}

	if addr != nil {
		ip := addr.IP.To4()
		if ip != nil {
			copy(reply[4:8], ip)
		}
		binary.BigEndian.PutUint16(reply[8:10], uint16(addr.Port))
	}

	_, err := conn.Write(reply)
	return err
}
