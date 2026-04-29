# caep.dev — CAEP end-to-end demo

A working demo of the **Continuous Access Evaluation Profile (CAEP)**: a mock
transmitter and a receiver that talk to each other over the Shared Signals
Framework, with an admin UI for triggering security events and watching them
flow to the receiver in real time.

```
┌────────────────────┐     SSF management API      ┌───────────────────┐
│   Transmitter      │ ◀────────────────────────── │     Receiver      │
│  (mock, this repo) │                             │  (this repo)      │
│                    │ ──── push signed SETs ────▶ │                   │
│   admin UI ─┐      │                             │   /events handler │
└─────────────┼──────┘                             └───────────────────┘
              │
        click "Trigger" →  build SecEvent → sign with ES256 → POST to /events
```

---

## Quick start

### 0. Install Go (one-time setup)

#### 0.1 macOS (Homebrew)

```bash
brew install go
```

### 0.1 Linux (apt or snap)

```bash
sudo apt update
sudo apt install -y golang-go
```

### --- OR ---

```bash
sudo snap install go --classic
```

### 0.2 Confirm Go install (should return something like "go version go1.xx.x <os>/<arch>")

```bash
go version
```

### 0.3 Install dependencies

```bash
go mod tidy
```

### 1. Run the demo

```bash
# terminal 1 — transmitter on :8080 (admin UI at /)
cd transmitter && go run ./...

# terminal 2 — receiver on :9000, auto-registers a stream
cd receiver && go run ./...
```

Open <http://localhost:8080/>, pick a stream and an event type, click **Push event**.
The receiver's terminal will print the parsed event.

---

## What is CAEP?

CAEP is a three-layer cake:

| Layer    | Spec                                                                                                              | What it gives you                                        |
| -------- | ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| **SET**  | [RFC 8417](https://www.rfc-editor.org/rfc/rfc8417)                                                                | A JWT shape for delivering one security event            |
| **SSF**  | [OpenID Shared Signals Framework](https://openid.github.io/sharedsignals/openid-sharedsignals-framework-1_0.html) | The HTTP API and roles for managing event streams        |
| **CAEP** | [OpenID CAEP](https://openid.github.io/sharedsignals/openid-caep-1_0.html)                                        | A vocabulary of access-related event types on top of SSF |

The motivating problem: an OAuth access token is normally issued for, say, an
hour. If something bad happens in the meantime (session revoked, device falls
out of compliance, MFA assurance drops, claims change), the relying party has
no way to know until the token expires. CAEP defines the events; SSF defines
how to deliver them.

### Roles

- **Transmitter** — the party that _knows about_ security events (an IdP, an
  MDM, a session manager). It owns a signing key, exposes a discovery
  document, and emits SETs.
- **Receiver** — the party that _acts on_ events (a relying party, a
  resource server, a downstream gateway). It registers a stream with the
  transmitter, telling it which event types it wants and where to deliver them.

### Security Event Token (SET)

A SET is a JWT with a specific shape. Example, decoded:

```json
{
  "iss": "http://localhost:8080",
  "aud": ["http://localhost:9000/events"],
  "iat": 1777234056,
  "jti": "28fda119-a428-49eb-a97d-fa2cb04c3dbd",
  "sub_id": { "format": "email", "email": "alice@example.com" },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change": {
      "current_level": "nist-aal1",
      "previous_level": "nist-aal2",
      "change_direction": "decrease",
      "event_timestamp": 1777234056
    }
  }
}
```

Notable things:

- The JWT is signed with the transmitter's key (`ES256` in this demo). The
  receiver fetches `jwks_uri` from the discovery document to verify.
- The `events` claim is a _map_ keyed by an event-type URI. One SET = one
  event in CAEP (multi-event SETs exist but are rarely used).
- The `sub_id` is the subject the event is _about_ — could be an email, a
  phone number, an opaque string, or a complex subject combining multiple
  identifiers (e.g., user + device).
- The JWT header carries `typ: secevent+jwt` so receivers can tell SETs apart
  from regular access tokens.

### Stream lifecycle (SSF)

A _stream_ is the receiver's subscription. It has its own ID, status, list of
requested event types, and a delivery configuration.

```
┌──────────────┐  POST /ssf/streams       ┌──────────────┐
│              │ ────────────────────────▶│              │
│   Receiver   │                          │ Transmitter  │
│              │ ◀──── 201 + StreamConfig │              │
└──────────────┘                          └──────────────┘
        │
        │  POST /ssf/subjects:add  (track who to send events about)
        │  POST /ssf/verify        (transmitter pushes a no-op SET to confirm channel)
        │  POST /ssf/status        (pause / resume / disable)
        │  PUT  /ssf/streams       (change requested events or push endpoint)
        │  DELETE /ssf/streams     (tear it down)
        ▼
```

Stream status transitions:

- **enabled** — transmitter must transmit events as they happen
- **paused** — transmitter must hold events but not deliver them
- **disabled** — transmitter must drop events, not hold them

### Delivery: push vs poll

Two delivery profiles, identified by URN in the stream config:

- **Push** (`urn:ietf:rfc:8935`) — transmitter `POST`s each SET to a URL the
  receiver gave it. Lower latency, but the receiver must run an HTTP endpoint
  reachable by the transmitter.
- **Poll** (`urn:ietf:rfc:8936`) — receiver periodically `POST`s to the
  transmitter, which returns a batch of pending SETs. Receiver acknowledges
  by JTI to remove them from the queue. Works behind firewalls.

**This demo is push-based.** Adding poll would mean a `POST /ssf/streams/poll`
endpoint on the transmitter that drains a per-stream queue.

### CAEP event types

The five event types CAEP defines (all under
`https://schemas.openid.net/secevent/caep/event-type/...`):

| Event                      | Meaning                                                                     |
| -------------------------- | --------------------------------------------------------------------------- |
| `session-revoked`          | A session has been terminated. Receiver should sign the user out.           |
| `credential-change`        | A credential was created/updated/deleted/revoked (password, FIDO key, etc.) |
| `assurance-level-change`   | Authentication assurance changed (e.g., AAL2 → AAL1).                       |
| `device-compliance-change` | Device went compliant ↔ non-compliant.                                      |
| `token-claims-change`      | Claims attached to an existing token changed (e.g., role demotion).         |

Each event payload carries common CAEP metadata: `event_timestamp`,
`initiating_entity` (`admin` / `user` / `policy` / `system`), and human
reasons (`reason_admin`, `reason_user`).

---

## Repository layout

| Path                                          | Role                                                                                           |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| [`secevent/`](./secevent)                     | Library: build, sign, parse, validate SETs (RFC 8417).                                         |
| [`ssfreceiver/`](./ssfreceiver)               | Library: receiver-side SSF — stream setup, push/poll, subjects, verify.                        |
| [`transmitter/`](./transmitter)               | **Demo** mock transmitter. Implements the SSF management API + admin UI for triggering events. |
| [`receiver/`](./receiver)                     | **Demo** receiver binary. Wraps `ssfreceiver` + a `/events` HTTP handler.                      |
| [`postman-collection/`](./postman-collection) | Postman collection documenting every transmitter endpoint. Useful as a spec reference.         |

---

## Running the demo

### 1. Start the transmitter

```bash
cd transmitter
go run ./...
```

Output:

```
mock CAEP transmitter listening on :8080 (issuer=http://localhost:8080)
admin UI:        http://localhost:8080/
metadata:        http://localhost:8080/.well-known/ssf-configuration
jwks:            http://localhost:8080/jwks.json
bearer token:    "demo-token" (use empty -token to disable auth)
```

The transmitter generates a fresh ES256 keypair on startup and serves the
public half at `/jwks.json`. Streams live in memory.

### 2. Start the receiver

```bash
cd receiver
go run ./...
```

What it does on startup:

1. Binds `/events` on `:9000` to handle incoming SETs.
2. Calls `builder.Setup(ctx)` from the `ssfreceiver` library, which:
   - `GET /.well-known/ssf-configuration` — discover the transmitter's endpoints.
   - `POST /ssf/streams` — create a stream with push delivery to
     `http://localhost:9000/events` and the five CAEP event types.
3. Logs the assigned stream ID and waits.

Add `-verify-set` to validate signatures against the transmitter's JWKS plus
`iss` and `aud` claims (off by default to keep the demo turn-key).

### 3. Trigger an event

Open <http://localhost:8080/>:

1. **Registered Streams** lists every stream the transmitter knows about. The
   receiver registered one on startup; refresh if you don't see it.
2. **Trigger an Event** form: pick the stream, choose an event type, enter a
   subject email, optionally fill in event-specific knobs in the **Extra
   fields** JSON box, click **Push event**.
3. **Verify Stream** sends an SSF verification SET — a no-op event whose only
   job is to prove the push channel is live. The receiver should log
   `verification state: "..."` echoing the value you sent.

You can also trigger from the CLI:

```bash
curl -X POST http://localhost:8080/admin/trigger \
  -H 'Content-Type: application/json' \
  -d '{
    "stream_id": "stream-...",
    "event_type": "https://schemas.openid.net/secevent/caep/event-type/credential-change",
    "email": "alice@example.com",
    "credential_type": "fido2-roaming",
    "change_type": "create",
    "reason": "user enrolled new key"
  }'
```

### What happens under the hood when you click Trigger

1. Admin UI POSTs `/admin/trigger` on the transmitter.
2. Transmitter looks up the stream record by ID.
3. It uses `secevent` to build a CAEP event (e.g., `caep.NewCredentialChangeEvent(...)`),
   wraps it in a SecEvent with the stream's push endpoint as `aud`, and signs with ES256.
4. It `POST`s the resulting JWT to the stream's `endpoint_url` with
   `Content-Type: application/secevent+jwt`.
5. The receiver's `/events` handler reads the body, parses with
   `parser.NewParser()`, switches on `secEvent.Event.Type()`, and prints details.

If the stream is `paused` or `disabled`, the transmitter refuses to push
(returns 502 to the admin UI). Resume the stream from the UI or via:

```bash
curl -X POST http://localhost:8080/ssf/status \
  -H 'Authorization: Bearer demo-token' -H 'Content-Type: application/json' \
  -d '{"stream_id":"stream-...","status":"enabled"}'
```

---

## Going further

- **Real signature verification.** Run the receiver with `-verify-set` to
  enable JWKS-based verification. The receiver will reject SETs that don't
  verify, have the wrong issuer, or aren't aimed at its push endpoint.
- **Subject management.** Use `stream.AddSubject(ctx, sub)` from the
  ssfreceiver library, or `POST /ssf/subjects:add` directly. The transmitter
  stores subjects in memory; in a real deployment the transmitter would only
  emit events about explicitly-added subjects (or all of them, depending on
  the `default_subjects` metadata setting).
- **Custom event types.** CAEP isn't the only profile. You can mint your own
  event-type URI and ship it in a SET — see
  [`ssfreceiver/README.md` § Custom Events](./ssfreceiver/README.md#custom-events).
- **Adding poll delivery.** Implement `POST /ssf/streams/poll` on the
  transmitter that returns and acknowledges queued SETs. The receiver-side
  poll path is already in `ssfreceiver`.

## Libraries (consumed by both demo binaries)

### [secevent](./secevent)

Builds, signs, parses, and validates SETs per [RFC 8417](https://www.rfc-editor.org/rfc/rfc8417).
Covers the CAEP and SSF event vocabularies and supports custom event types.

### [ssfreceiver](./ssfreceiver)

Receiver-side SSF: stream creation, push/poll delivery, subject management,
verification, status lifecycle.

## Contributing

Contributions are welcome — feature enhancements, bug fixes, and documentation
improvements.
