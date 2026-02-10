module steady-shadowtls

go 1.21

require (
	github.com/metacubex/sing v0.5.2
	github.com/metacubex/sing-shadowtls v0.0.0-20250503063515-5d9f966d17a2
	github.com/sirupsen/logrus v1.9.4
	shadowtls-tunnel v0.0.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/refraction-networking/utls v1.6.7 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace shadowtls-tunnel => ..
