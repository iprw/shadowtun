package shadowtls

import (
	"context"
	"net"

	sing_shadowtls "github.com/metacubex/sing-shadowtls"
	utls "github.com/refraction-networking/utls"
)

// CreateHandshakeFunc creates a TLS handshake function that uses uTLS
// with custom SessionID generation for ShadowTLS v3 authentication.
func CreateHandshakeFunc(sni string) sing_shadowtls.TLSHandshakeFunc {
	return func(ctx context.Context, conn net.Conn, sessionIDGenerator sing_shadowtls.TLSSessionIDGeneratorFunc) error {
		tlsConfig := &utls.Config{
			ServerName: sni,
			// Certificate verification is intentionally skipped: ShadowTLS
			// authenticates via HMAC in the TLS SessionID, not via the
			// certificate chain. The TLS handshake is camouflage only.
			InsecureSkipVerify: true,
		}

		uconn := utls.UClient(conn, tlsConfig, utls.HelloChrome_Auto)

		if err := uconn.BuildHandshakeState(); err != nil {
			return err
		}

		if sessionIDGenerator != nil {
			clientHelloBytes := uconn.HandshakeState.Hello.Raw
			sessionID := make([]byte, 32)
			if err := sessionIDGenerator(clientHelloBytes, sessionID); err != nil {
				return err
			}
			uconn.HandshakeState.Hello.SessionId = sessionID
			if err := uconn.BuildHandshakeState(); err != nil {
				return err
			}
		}

		return uconn.HandshakeContext(ctx)
	}
}
