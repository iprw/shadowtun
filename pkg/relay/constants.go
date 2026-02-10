package relay

import "time"

const (
	// DefaultIdleTimeout is the read deadline applied between data chunks.
	// Connections idle longer than this are considered dead.
	DefaultIdleTimeout = 5 * time.Minute

	// DefaultWriteTimeout is the write deadline for each write operation.
	DefaultWriteTimeout = 30 * time.Second

	// bufSize is the buffer size used for copying data.
	bufSize = 32 * 1024
)
