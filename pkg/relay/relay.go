package relay

import (
	"net"
	"time"
)

// CopyConn copies data from src to dst with idle and write timeouts to prevent
// ghost connections. It blocks until src returns an error (including EOF/timeout)
// or a write to dst fails.
func CopyConn(dst, src net.Conn, idleTimeout, writeTimeout time.Duration) {
	buf := make([]byte, bufSize)
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
