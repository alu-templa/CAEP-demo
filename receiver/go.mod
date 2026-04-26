module github.com/sgnl-ai/caep.dev/receiver

go 1.25

require (
	github.com/sgnl-ai/caep.dev/secevent v0.0.0
	github.com/sgnl-ai/caep.dev/ssfreceiver v0.0.0
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.3 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.6 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/jwx/v2 v2.1.6 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/oauth2 v0.33.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
)

replace (
	github.com/sgnl-ai/caep.dev/secevent => ../secevent
	github.com/sgnl-ai/caep.dev/ssfreceiver => ../ssfreceiver
)
