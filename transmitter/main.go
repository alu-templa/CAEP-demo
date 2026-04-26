package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/sgnl-ai/caep.dev/secevent/pkg/builder"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/id"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/signing"
)

const keyID = "demo-key-1"

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	issuer := flag.String("issuer", "http://localhost:8080", "transmitter issuer URL (use the externally reachable URL when receiver runs elsewhere)")
	bearer := flag.String("token", "demo-token", "bearer token receivers must present (empty disables auth)")
	flag.Parse()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate signing key: %v", err)
	}

	signer, err := signing.NewSigner(privKey, signing.WithKeyID(keyID))
	if err != nil {
		log.Fatalf("failed to create signer: %v", err)
	}

	tx := &Transmitter{
		Issuer:  *issuer,
		Token:   *bearer,
		PrivKey: privKey,
		Signer:  signer,
		Builder: builder.NewBuilder(
			builder.WithDefaultIssuer(*issuer),
			builder.WithDefaultIDGenerator(id.NewUUIDGenerator()),
		),
		Streams:    make(map[string]*StreamRec),
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}

	mux := http.NewServeMux()
	tx.RegisterRoutes(mux)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           withLogging(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("mock CAEP transmitter listening on %s (issuer=%s)", *addr, *issuer)
	log.Printf("admin UI:        %s/", *issuer)
	log.Printf("metadata:        %s/.well-known/ssf-configuration", *issuer)
	log.Printf("jwks:            %s/jwks.json", *issuer)
	log.Printf("bearer token:    %q (use empty -token to disable auth)", *bearer)

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
	_ = context.Background
}

func withLogging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingRW{ResponseWriter: w, status: 200}
		h.ServeHTTP(lrw, r)
		log.Printf("%-6s %-32s -> %d (%s)", r.Method, r.URL.RequestURI(), lrw.status, time.Since(start))
	})
}

type loggingRW struct {
	http.ResponseWriter
	status int
}

func (l *loggingRW) WriteHeader(code int) {
	l.status = code
	l.ResponseWriter.WriteHeader(code)
}
