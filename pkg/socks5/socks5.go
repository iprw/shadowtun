package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	Version = 0x05

	// Auth methods
	authNone     = 0x00
	authPassword = 0x02
	authNoAccept = 0xFF

	// Commands
	cmdConnect = 0x01

	// Address types
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	// Reply codes
	repSuccess          = 0x00
	repHostUnreach      = 0x04
	repCmdNotSupported  = 0x07
	repAtypNotSupported = 0x08

	idleTimeout  = 5 * time.Minute
	writeTimeout = 30 * time.Second
)

// Handler handles SOCKS5 protocol on a connection.
type Handler struct {
	username string
	password string
	logger   *logrus.Logger
}

// NewHandler creates a new SOCKS5 handler.
func NewHandler(username, password string, logger *logrus.Logger) *Handler {
	return &Handler{
		username: username,
		password: password,
		logger:   logger,
	}
}

// Handle processes a SOCKS5 connection.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	if err := h.handshake(conn); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

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

func (h *Handler) handleConnect(conn net.Conn, target string) error {
	h.logger.Infof("SOCKS5 CONNECT to %s", target)

	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		h.sendReply(conn, repHostUnreach, nil)
		return fmt.Errorf("connect to %s failed: %w", target, err)
	}
	defer targetConn.Close()

	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	if err := h.sendReply(conn, repSuccess, localAddr); err != nil {
		return fmt.Errorf("send reply failed: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		copyConn(targetConn, conn)
		targetConn.(*net.TCPConn).CloseWrite()
	}()

	go func() {
		defer wg.Done()
		copyConn(conn, targetConn)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	return nil
}

// copyConn copies data with idle and write timeouts to prevent ghost connections.
func copyConn(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			dst.SetWriteDeadline(time.Now().Add(writeTimeout))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (h *Handler) handshake(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != Version {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	needAuth := h.username != "" && h.password != ""

	if needAuth {
		if !slices.Contains(methods, authPassword) {
			conn.Write([]byte{Version, authNoAccept})
			return fmt.Errorf("client doesn't support password auth")
		}

		if _, err := conn.Write([]byte{Version, authPassword}); err != nil {
			return fmt.Errorf("write auth method: %w", err)
		}

		if err := h.readAuth(conn); err != nil {
			return err
		}
	} else {
		if !slices.Contains(methods, authNone) {
			conn.Write([]byte{Version, authNoAccept})
			return fmt.Errorf("client doesn't support no-auth")
		}
		if _, err := conn.Write([]byte{Version, authNone}); err != nil {
			return fmt.Errorf("write auth method: %w", err)
		}
	}

	return nil
}

func (h *Handler) readAuth(conn net.Conn) error {
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return err
	}
	if version[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", version[0])
	}

	ulen := make([]byte, 1)
	if _, err := io.ReadFull(conn, ulen); err != nil {
		return err
	}
	username := make([]byte, ulen[0])
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}
	password := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	if string(username) != h.username || string(password) != h.password {
		conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("auth failed")
	}

	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return fmt.Errorf("write auth success: %w", err)
	}
	return nil
}

func (h *Handler) readRequest(conn net.Conn) (cmd byte, addr string, err error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, "", err
	}

	if header[0] != Version {
		return 0, "", fmt.Errorf("unsupported version: %d", header[0])
	}

	cmd = header[1]

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

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return 0, "", err
	}
	port := binary.BigEndian.Uint16(portBytes)

	return cmd, fmt.Sprintf("%s:%d", host, port), nil
}

func (h *Handler) sendReply(conn net.Conn, rep byte, addr *net.TCPAddr) error {
	reply := []byte{Version, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}

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
