module github.com/sgnl-ai/caep.dev/transmitter

go 1.25

require github.com/sgnl-ai/caep.dev/secevent v0.0.0

require (
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
)

replace github.com/sgnl-ai/caep.dev/secevent => ../secevent
