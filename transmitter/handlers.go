package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sgnl-ai/caep.dev/secevent/pkg/event"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/schemes/caep"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/schemes/ssf"
	"github.com/sgnl-ai/caep.dev/secevent/pkg/subject"
)

//go:embed web/index.html
var indexHTML []byte

var supportedEvents = []event.EventType{
	caep.EventTypeSessionRevoked,
	caep.EventTypeCredentialChange,
	caep.EventTypeAssuranceLevelChange,
	caep.EventTypeDeviceComplianceChange,
	caep.EventTypeTokenClaimsChange,
	ssf.EventTypeVerification,
}

func (t *Transmitter) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/ssf-configuration", t.handleMetadata)
	mux.HandleFunc("/jwks.json", t.handleJWKS)

	mux.HandleFunc("/ssf/streams", t.requireAuth(t.handleStreams))
	mux.HandleFunc("/ssf/status", t.requireAuth(t.handleStatus))
	mux.HandleFunc("/ssf/subjects:add", t.requireAuth(t.handleAddSubject))
	mux.HandleFunc("/ssf/subjects:remove", t.requireAuth(t.handleRemoveSubject))
	mux.HandleFunc("/ssf/verify", t.requireAuth(t.handleVerify))

	mux.HandleFunc("/admin/trigger", t.handleAdminTrigger)
	mux.HandleFunc("/admin/streams", t.handleAdminStreams)
	mux.HandleFunc("/", t.handleIndex)
}

func (t *Transmitter) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !t.authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func (t *Transmitter) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

// ---- Transmitter Metadata ------------------------------------------------

func (t *Transmitter) handleMetadata(w http.ResponseWriter, r *http.Request) {
	body := map[string]any{
		"spec_version":               "1_0-ID3",
		"issuer":                     t.Issuer,
		"jwks_uri":                   t.Issuer + "/jwks.json",
		"delivery_methods_supported": []string{"urn:ietf:rfc:8935"},
		"configuration_endpoint":     t.Issuer + "/ssf/streams",
		"status_endpoint":            t.Issuer + "/ssf/status",
		"add_subject_endpoint":       t.Issuer + "/ssf/subjects:add",
		"remove_subject_endpoint":    t.Issuer + "/ssf/subjects:remove",
		"verification_endpoint":      t.Issuer + "/ssf/verify",
		"authorization_schemes":      []map[string]string{{"spec_urn": "urn:ietf:rfc:6749"}},
	}
	writeJSON(w, http.StatusOK, body)
}

func (t *Transmitter) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, t.jwksJSON())
}

// ---- Stream CRUD --------------------------------------------------------

func (t *Transmitter) handleStreams(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		t.createStream(w, r)
	case http.MethodGet:
		t.getStream(w, r)
	case http.MethodPut:
		t.replaceStream(w, r)
	case http.MethodDelete:
		t.deleteStream(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type streamRequest struct {
	StreamID        string `json:"stream_id,omitempty"`
	Delivery        *struct {
		Method              string `json:"method"`
		EndpointURL         string `json:"endpoint_url"`
		AuthorizationHeader string `json:"authorization_header,omitempty"`
	} `json:"delivery,omitempty"`
	EventsRequested []event.EventType `json:"events_requested,omitempty"`
	Description     string            `json:"description,omitempty"`
}

func (t *Transmitter) createStream(w http.ResponseWriter, r *http.Request) {
	var req streamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Delivery == nil {
		http.Error(w, "delivery is required", http.StatusBadRequest)
		return
	}
	if req.Delivery.Method != "urn:ietf:rfc:8935" {
		http.Error(w, "this transmitter only supports push delivery (urn:ietf:rfc:8935)", http.StatusBadRequest)
		return
	}
	if _, err := url.Parse(req.Delivery.EndpointURL); err != nil || req.Delivery.EndpointURL == "" {
		http.Error(w, "delivery.endpoint_url is required and must be a valid URL", http.StatusBadRequest)
		return
	}
	if len(req.EventsRequested) == 0 {
		http.Error(w, "events_requested must contain at least one event type", http.StatusBadRequest)
		return
	}

	rec := &StreamRec{
		ID:              t.newStreamID(),
		Description:     req.Description,
		DeliveryMethod:  req.Delivery.Method,
		PushEndpoint:    req.Delivery.EndpointURL,
		PushAuthHeader:  req.Delivery.AuthorizationHeader,
		EventsRequested: filterSupported(req.EventsRequested),
		Status:          "enabled",
	}

	t.Mu.Lock()
	t.Streams[rec.ID] = rec
	t.Mu.Unlock()

	writeJSON(w, http.StatusCreated, t.configResponse(rec))
}

func (t *Transmitter) getStream(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("stream_id")
	t.Mu.Lock()
	defer t.Mu.Unlock()

	if id == "" {
		out := make([]map[string]any, 0, len(t.Streams))
		for _, s := range t.Streams {
			out = append(out, t.configResponse(s))
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	rec, ok := t.Streams[id]
	if !ok {
		http.Error(w, "stream not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, t.configResponse(rec))
}

func (t *Transmitter) replaceStream(w http.ResponseWriter, r *http.Request) {
	var req streamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.StreamID == "" {
		http.Error(w, "stream_id is required", http.StatusBadRequest)
		return
	}

	t.Mu.Lock()
	defer t.Mu.Unlock()

	rec, ok := t.Streams[req.StreamID]
	if !ok {
		http.Error(w, "stream not found", http.StatusNotFound)
		return
	}
	if req.Delivery != nil {
		rec.DeliveryMethod = req.Delivery.Method
		rec.PushEndpoint = req.Delivery.EndpointURL
		if req.Delivery.AuthorizationHeader != "" {
			rec.PushAuthHeader = req.Delivery.AuthorizationHeader
		}
	}
	if len(req.EventsRequested) > 0 {
		rec.EventsRequested = filterSupported(req.EventsRequested)
	}
	if req.Description != "" {
		rec.Description = req.Description
	}
	writeJSON(w, http.StatusOK, t.configResponse(rec))
}

func (t *Transmitter) deleteStream(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("stream_id")
	if id == "" {
		http.Error(w, "stream_id is required", http.StatusBadRequest)
		return
	}
	t.Mu.Lock()
	delete(t.Streams, id)
	t.Mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (t *Transmitter) configResponse(rec *StreamRec) map[string]any {
	return map[string]any{
		"stream_id": rec.ID,
		"iss":       t.Issuer,
		"aud":       rec.PushEndpoint,
		"delivery": map[string]string{
			"method":       rec.DeliveryMethod,
			"endpoint_url": rec.PushEndpoint,
		},
		"events_supported": supportedEvents,
		"events_requested": rec.EventsRequested,
		"events_delivered": rec.EventsRequested,
		"description":      rec.Description,
	}
}

// ---- Stream Status ------------------------------------------------------

func (t *Transmitter) handleStatus(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("stream_id")
		t.Mu.Lock()
		rec, ok := t.Streams[id]
		t.Mu.Unlock()
		if !ok {
			http.Error(w, "stream not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"stream_id": rec.ID,
			"status":    rec.Status,
			"reason":    rec.StatusReason,
		})
	case http.MethodPost:
		var req struct {
			StreamID string `json:"stream_id"`
			Status   string `json:"status"`
			Reason   string `json:"reason,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		switch req.Status {
		case "enabled", "paused", "disabled":
		default:
			http.Error(w, "invalid status", http.StatusBadRequest)
			return
		}
		t.Mu.Lock()
		rec, ok := t.Streams[req.StreamID]
		if ok {
			rec.Status = req.Status
			rec.StatusReason = req.Reason
		}
		t.Mu.Unlock()
		if !ok {
			http.Error(w, "stream not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- Subjects -----------------------------------------------------------

func (t *Transmitter) handleAddSubject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		StreamID string          `json:"stream_id"`
		Subject  json.RawMessage `json:"subject"`
		Verified bool            `json:"verified,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	sub, err := subject.ParseSubject(req.Subject)
	if err != nil {
		http.Error(w, "invalid subject: "+err.Error(), http.StatusBadRequest)
		return
	}
	t.Mu.Lock()
	rec, ok := t.Streams[req.StreamID]
	if ok {
		rec.Subjects = append(rec.Subjects, sub)
	}
	t.Mu.Unlock()
	if !ok {
		http.Error(w, "stream not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (t *Transmitter) handleRemoveSubject(w http.ResponseWriter, r *http.Request) {
	// Subject removal is best-effort in this demo: we drop any with the same JSON shape.
	var req struct {
		StreamID string          `json:"stream_id"`
		Subject  json.RawMessage `json:"subject"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	target, err := subject.ParseSubject(req.Subject)
	if err != nil {
		http.Error(w, "invalid subject: "+err.Error(), http.StatusBadRequest)
		return
	}
	targetJSON, _ := json.Marshal(target)

	t.Mu.Lock()
	rec, ok := t.Streams[req.StreamID]
	if ok {
		kept := rec.Subjects[:0]
		for _, s := range rec.Subjects {
			b, _ := json.Marshal(s)
			if string(b) != string(targetJSON) {
				kept = append(kept, s)
			}
		}
		rec.Subjects = kept
	}
	t.Mu.Unlock()
	if !ok {
		http.Error(w, "stream not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ---- Stream Verification -------------------------------------------------

func (t *Transmitter) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		StreamID string `json:"stream_id"`
		State    string `json:"state,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	t.Mu.Lock()
	rec, ok := t.Streams[req.StreamID]
	t.Mu.Unlock()
	if !ok {
		http.Error(w, "stream not found", http.StatusNotFound)
		return
	}

	verifyEvent := ssf.NewVerificationEvent()
	if req.State != "" {
		verifyEvent.WithState(req.State)
	}
	sub, _ := subject.NewOpaqueSubject(rec.ID)
	secEvent := t.Builder.NewSecEvent().
		WithAudience(rec.PushEndpoint).
		WithSubject(sub).
		WithEvent(verifyEvent)

	if err := t.pushSecEvent(r.Context(), rec, secEvent); err != nil {
		http.Error(w, "push failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ---- Admin: trigger an event push ----------------------------------------

type triggerRequest struct {
	StreamID  string `json:"stream_id"`
	EventType string `json:"event_type"`
	Email     string `json:"email,omitempty"`
	Reason    string `json:"reason,omitempty"`

	// Event-specific knobs
	CredentialType string `json:"credential_type,omitempty"`
	ChangeType     string `json:"change_type,omitempty"`
	CurrentLevel   string `json:"current_level,omitempty"`
	PreviousLevel  string `json:"previous_level,omitempty"`
	CurrentStatus  string `json:"current_status,omitempty"`
	PreviousStatus string `json:"previous_status,omitempty"`
	Claims         map[string]any `json:"claims,omitempty"`
}

func (t *Transmitter) handleAdminTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req triggerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	t.Mu.Lock()
	rec, ok := t.Streams[req.StreamID]
	t.Mu.Unlock()
	if !ok {
		http.Error(w, "stream not found", http.StatusNotFound)
		return
	}

	if req.Email == "" {
		req.Email = "demo-user@example.com"
	}
	sub, err := subject.NewEmailSubject(req.Email)
	if err != nil {
		http.Error(w, "invalid email: "+err.Error(), http.StatusBadRequest)
		return
	}

	evt, err := buildEvent(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	secEvent := t.Builder.NewSecEvent().
		WithAudience(rec.PushEndpoint).
		WithSubject(sub).
		WithEvent(evt)

	if err := t.pushSecEvent(r.Context(), rec, secEvent); err != nil {
		http.Error(w, "push failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "pushed"})
}

func buildEvent(req triggerRequest) (event.Event, error) {
	now := time.Now().Unix()

	switch event.EventType(req.EventType) {
	case caep.EventTypeSessionRevoked:
		e := caep.NewSessionRevokedEvent().
			WithInitiatingEntity(caep.InitiatingEntityPolicy).
			WithEventTimestamp(now)
		if req.Reason != "" {
			e.WithReasonAdmin("en", req.Reason)
		}
		return e, nil

	case caep.EventTypeCredentialChange:
		credType := caep.CredentialType(orDefault(req.CredentialType, string(caep.CredentialTypePassword)))
		changeType := caep.ChangeType(orDefault(req.ChangeType, string(caep.ChangeTypeUpdate)))
		e := caep.NewCredentialChangeEvent(credType, changeType).
			WithInitiatingEntity(caep.InitiatingEntityUser).
			WithEventTimestamp(now)
		if req.Reason != "" {
			e.WithReasonUser("en", req.Reason)
		}
		return e, nil

	case caep.EventTypeAssuranceLevelChange:
		cur := caep.AssuranceLevel(orDefault(req.CurrentLevel, string(caep.AssuranceLevelAAL2)))
		prev := caep.AssuranceLevel(orDefault(req.PreviousLevel, string(caep.AssuranceLevelAAL1)))
		direction := caep.ChangeDirectionIncrease
		if cur < prev {
			direction = caep.ChangeDirectionDecrease
		}
		e := caep.NewAssuranceLevelChangeEvent(cur, prev, direction).
			WithEventTimestamp(now)
		if req.Reason != "" {
			e.WithReasonAdmin("en", req.Reason)
		}
		return e, nil

	case caep.EventTypeDeviceComplianceChange:
		cur := caep.ComplianceStatus(orDefault(req.CurrentStatus, string(caep.ComplianceStatusNotCompliant)))
		prev := caep.ComplianceStatus(orDefault(req.PreviousStatus, string(caep.ComplianceStatusCompliant)))
		e := caep.NewDeviceComplianceChangeEvent(cur, prev)
		e.WithEventTimestamp(now)
		if req.Reason != "" {
			e.WithReasonAdmin("en", req.Reason)
		}
		return e, nil

	case caep.EventTypeTokenClaimsChange:
		e := caep.NewTokenClaimsChangeEvent().WithEventTimestamp(now)
		claims := req.Claims
		if len(claims) == 0 {
			claims = map[string]any{"role": "demoted-user"}
		}
		for k, v := range claims {
			e.WithClaim(k, v)
		}
		if req.Reason != "" {
			e.WithReasonAdmin("en", req.Reason)
		}
		return e, nil
	}
	return nil, fmt.Errorf("unsupported event_type %q", req.EventType)
}

// ---- Admin: list streams (used by the UI) --------------------------------

func (t *Transmitter) handleAdminStreams(w http.ResponseWriter, r *http.Request) {
	t.Mu.Lock()
	defer t.Mu.Unlock()
	out := make([]map[string]any, 0, len(t.Streams))
	for _, s := range t.Streams {
		out = append(out, map[string]any{
			"stream_id":        s.ID,
			"description":      s.Description,
			"endpoint_url":     s.PushEndpoint,
			"status":           s.Status,
			"events_requested": s.EventsRequested,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- helpers -------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func filterSupported(in []event.EventType) []event.EventType {
	out := make([]event.EventType, 0, len(in))
	for _, t := range in {
		for _, s := range supportedEvents {
			if t == s {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

func orDefault(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}
