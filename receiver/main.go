package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/sgnl-ai/caep.dev/secevent/pkg/event"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/parser"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/schemes/caep"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/schemes/ssf"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/token"
	"github.com/sgnl-ai/caep.dev/ssfreceiver/auth"
	"github.com/sgnl-ai/caep.dev/ssfreceiver/builder"
)

func main() {
	transmitterMeta := flag.String("transmitter", "http://localhost:8080/.well-known/ssf-configuration", "transmitter metadata URL")
	receiverURL := flag.String("receiver", "http://localhost:9000", "this receiver's externally reachable base URL")
	listen := flag.String("listen", ":9000", "address to listen on for pushed events")
	bearer := flag.String("token", "demo-token", "bearer token to send to the transmitter")
	verify := flag.Bool("verify-set", false, "verify SET signatures against the transmitter's JWKS (recommended for real use)")
	flag.Parse()

	pushEndpoint := strings.TrimRight(*receiverURL, "/") + "/events"

	// Parser: by default we skip signature verification so the demo just works.
	// With -verify-set the parser fetches the transmitter's JWKS and validates signatures + iss + aud.
	var p *parser.Parser
	if *verify {
		jwksURL := metadataIssuerToJWKS(*transmitterMeta)
		p = parser.NewParser(
			parser.WithJWKSURL(jwksURL),
			parser.WithExpectedIssuer(strings.TrimSuffix(*transmitterMeta, "/.well-known/ssf-configuration")),
			parser.WithExpectedAudience(pushEndpoint),
		)
		log.Printf("SET verification ON (jwks=%s)", jwksURL)
	} else {
		p = parser.NewParser()
		log.Printf("SET verification OFF (use -verify-set to enable)")
	}

	// Start the push handler BEFORE registering the stream — otherwise the transmitter
	// could push (or send a verification SET) before we're listening.
	mux := http.NewServeMux()
	mux.HandleFunc("/events", makeHandler(p, *verify))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("receiver listening on %s, push endpoint = %s/events", *listen, *receiverURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	bearerAuth, err := auth.NewBearer(*bearer)
	if err != nil {
		log.Fatalf("bearer auth: %v", err)
	}

	streamBuilder, err := builder.New(
		*transmitterMeta,
		builder.WithPushDelivery(pushEndpoint),
		builder.WithAuth(bearerAuth),
		builder.WithEventTypes([]event.EventType{
			caep.EventTypeSessionRevoked,
			caep.EventTypeCredentialChange,
			caep.EventTypeAssuranceLevelChange,
			caep.EventTypeDeviceComplianceChange,
			caep.EventTypeTokenClaimsChange,
		}),
		builder.WithExistingCheck(),
		builder.WithDescription("local push-based demo receiver"),
	)
	if err != nil {
		log.Fatalf("build stream: %v", err)
	}

	stream, err := streamBuilder.Setup(context.Background())
	if err != nil {
		log.Fatalf("setup stream: %v", err)
	}
	log.Printf("stream registered: id=%s", stream.GetStreamID())
	log.Printf("ready - go to the transmitter UI and trigger an event")

	select {} // run until killed
}

func makeHandler(p *parser.Parser, verify bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var secEvent *token.SecEvent
		if verify {
			secEvent, err = p.ParseSecEvent(string(raw))
		} else {
			secEvent, err = p.ParseSecEventNoVerify(string(raw))
		}
		if err != nil {
			log.Printf("parse failed: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		describe(secEvent)
		w.WriteHeader(http.StatusOK)
	}
}

// describe pretty-prints what came in. Mirrors the switch in the upstream example
// but adds payload details for every CAEP event type.
func describe(e *token.SecEvent) {
	hdr := fmt.Sprintf("[%s] jti=%s", e.Event.Type(), e.ID)
	if iss, _ := e.GetIssuer(); iss != "" {
		hdr += " iss=" + iss
	}
	log.Printf("==== event received ====")
	log.Printf("%s", hdr)

	if sub, err := e.Subject.Payload(); err == nil {
		log.Printf("  subject: %+v", sub)
	}

	switch ev := e.Event.(type) {
	case *caep.SessionRevokedEvent:
		if r, ok := ev.GetReasonAdmin("en"); ok {
			log.Printf("  reason (admin): %s", r)
		}
	case *caep.CredentialChangeEvent:
		log.Printf("  credential_type=%s change_type=%s", ev.GetCredentialType(), ev.GetChangeType())
	case *caep.AssuranceLevelChangeEvent:
		log.Printf("  %s -> %s (%s)", ev.GetPreviousLevel(), ev.GetCurrentLevel(), ev.GetChangeDirection())
	case *caep.DeviceComplianceChangeEvent:
		log.Printf("  compliance: %s -> %s", ev.PreviousStatus, ev.CurrentStatus)
	case *caep.TokenClaimsChangeEvent:
		log.Printf("  claims: %+v", ev.Claims)
	case *ssf.VerificationEvent:
		if state, ok := ev.GetState(); ok {
			log.Printf("  verification state: %q", state)
		}
	default:
		log.Printf("  (no extra payload printer for type %s)", e.Event.Type())
	}
}

func metadataIssuerToJWKS(metaURL string) string {
	// http://host[:port]/.well-known/ssf-configuration -> http://host[:port]/jwks.json
	base := strings.TrimSuffix(metaURL, "/.well-known/ssf-configuration")
	return base + "/jwks.json"
}
