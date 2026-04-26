package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/sgnl-ai/caep.dev/secevent/pkg/builder"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/event"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/signing"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/subject"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/token"
)

// StreamRec is the in-memory record of a stream the transmitter has agreed to push to.
type StreamRec struct {
	ID                  string
	Description         string
	DeliveryMethod      string // urn:ietf:rfc:8935 (push) - poll not supported in this demo
	PushEndpoint        string
	PushAuthHeader      string
	EventsRequested     []event.EventType
	Status              string // enabled | paused | disabled
	StatusReason        string
	Subjects            []subject.Subject
}

type Transmitter struct {
	Issuer  string
	Token   string
	PrivKey *ecdsa.PrivateKey
	Signer  signing.Signer
	Builder *builder.Builder

	Mu      sync.Mutex
	Streams map[string]*StreamRec

	HTTPClient *http.Client
}

func (t *Transmitter) authorized(r *http.Request) bool {
	if t.Token == "" {
		return true
	}
	got := r.Header.Get("Authorization")
	return got == "Bearer "+t.Token
}

func (t *Transmitter) newStreamID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "stream-" + hex.EncodeToString(b[:])
}

// pushSecEvent signs the supplied SecEvent and POSTs it to the stream's push endpoint.
// Caller is responsible for setting the audience on the SecEvent before calling.
func (t *Transmitter) pushSecEvent(ctx context.Context, s *StreamRec, secEvent *token.SecEvent) error {
	if s.Status != "enabled" {
		return fmt.Errorf("stream %s is %s; not pushing", s.ID, s.Status)
	}

	signed, err := t.Signer.Sign(ctx, secEvent)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.PushEndpoint, bytes.NewReader([]byte(signed)))
	if err != nil {
		return fmt.Errorf("build push request: %w", err)
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")
	if s.PushAuthHeader != "" {
		req.Header.Set("Authorization", s.PushAuthHeader)
	}

	resp, err := t.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("push: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("receiver returned %s", resp.Status)
	}
	log.Printf("pushed SET to stream=%s receiver=%s status=%s", s.ID, s.PushEndpoint, resp.Status)
	return nil
}

// jwksJSON renders the transmitter's public key as a one-key JWKS.
// Manual JWK encoding avoids pulling in jwx as a direct dep.
func (t *Transmitter) jwksJSON() map[string]any {
	pub := t.PrivKey.PublicKey
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	x := pub.X.FillBytes(make([]byte, byteLen))
	y := pub.Y.FillBytes(make([]byte, byteLen))
	return map[string]any{
		"keys": []map[string]string{{
			"kty": "EC",
			"crv": "P-256",
			"kid": keyID,
			"use": "sig",
			"alg": "ES256",
			"x":   base64.RawURLEncoding.EncodeToString(x),
			"y":   base64.RawURLEncoding.EncodeToString(y),
		}},
	}
}
