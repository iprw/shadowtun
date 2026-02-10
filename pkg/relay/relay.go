package relay

import (
	"net"
	"time"
)

// CopyConn copies data from src to dst with idle and write timeouts to prevent
// ghost connections. It blocks until src returns an error (including EOF/timeout)
// or a write to dst fails.
func CopyConn(dst, src net.Conn, idleTimeout, writeTimeout time.Duration, onWrite func(n int)) (written int64, err error) {
	buf := make([]byte, bufSize)
	for {
		src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, rerr := src.Read(buf)
		if n > 0 {
			dst.SetWriteDeadline(time.Now().Add(writeTimeout))
			nw, werr := dst.Write(buf[:n])
			if nw > 0 {
				written += int64(nw)
				if onWrite != nil {
					onWrite(nw)
				}
			}
			if werr != nil {
				return written, werr
			}
		}
		if rerr != nil {
			return written, rerr
		}
	}
}
