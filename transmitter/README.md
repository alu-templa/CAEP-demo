# Mock CAEP Push Transmitter

A minimal SSF transmitter for demoing [CAEP](https://openid.github.io/sharedsignals/openid-caep-1_0.html) push delivery end-to-end against the [`ssfreceiver`](../ssfreceiver) library.

It implements the receiver-facing endpoints the `ssfreceiver` builder calls
during stream setup, plus an admin UI and `POST /admin/trigger` endpoint that
builds a signed [SET](https://www.rfc-editor.org/rfc/rfc8417) with the
[`secevent`](../secevent) library and pushes it to the registered stream's
`endpoint_url`.

## Run

```bash
go run ./...
# transmitter on :8080, bearer token "demo-token"
```

Useful flags:

- `-addr :8080` — listen address
- `-issuer http://localhost:8080` — used in metadata, JWT `iss`, JWKS URL
- `-token demo-token` — bearer token receivers must present (empty disables auth)

Open <http://localhost:8080/> for the admin UI.

## Endpoints

| Method | Path                                  | Purpose                                       |
| ------ | ------------------------------------- | --------------------------------------------- |
| GET    | `/.well-known/ssf-configuration`      | Transmitter metadata                          |
| GET    | `/jwks.json`                          | Public signing key (ES256, P-256)             |
| POST   | `/ssf/streams`                        | Create stream                                 |
| GET    | `/ssf/streams[?stream_id=]`           | List or fetch stream config                   |
| PUT    | `/ssf/streams`                        | Update stream config                          |
| DELETE | `/ssf/streams?stream_id=`             | Delete stream                                 |
| GET    | `/ssf/status?stream_id=`              | Get status                                    |
| POST   | `/ssf/status`                         | Update status (`enabled`, `paused`, `disabled`) |
| POST   | `/ssf/subjects:add`                   | Track subject (best-effort, in-memory)        |
| POST   | `/ssf/subjects:remove`                | Untrack subject                               |
| POST   | `/ssf/verify`                         | Build + push an SSF verification event        |
| POST   | `/admin/trigger`                      | Build + push a CAEP event (demo trigger)      |
| GET    | `/admin/streams`                      | List streams (UI helper, no auth)             |

The admin UI under `/` polls `/admin/streams` and posts to `/admin/trigger` and `/ssf/verify`.

## Wire it up to the receiver

Use [`ssfreceiver/examples/basic/push-based`](../ssfreceiver/examples/basic/push-based) as the receiver. Point its builder at:

```go
builder.New(
    "http://localhost:8080/.well-known/ssf-configuration",
    builder.WithPushDelivery("http://localhost:9000/events"),
    builder.WithAuth(auth.NewBearer("demo-token")),
    builder.WithEventTypes([]event.EventType{
        caep.EventTypeSessionRevoked,
        caep.EventTypeCredentialChange,
        caep.EventTypeAssuranceLevelChange,
        caep.EventTypeDeviceComplianceChange,
        caep.EventTypeTokenClaimsChange,
    }),
)
```

Then run an `http.Server` on `:9000` whose `/events` handler is the
`HandlePushedEvent` function from that example.

## Trigger an event from the CLI

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

## Limitations

- In-memory state only; restart wipes streams.
- Push delivery only (no poll). Adding poll = a `POST /ssf/streams/poll` handler that drains a per-stream queue.
- No SET signature verification on the receiver side in the example handler. Switch from `ParseSecEventNoVerify` to `ParseSecEvent` with `parser.WithJWKSURL("http://localhost:8080/jwks.json")` and `parser.WithExpectedIssuer("http://localhost:8080")` to get real validation.
- Bearer auth is single-token plaintext — for a real demo against an external receiver you probably want client-credentials.

## Upstream patch applied

[`secevent/pkg/schemes/caep/credential_change_event.go:58`](../secevent/pkg/schemes/caep/credential_change_event.go#L58) had a copy-paste bug — `NewCredentialChangeEvent` called `e.SetType(EventTypeAssuranceLevelChange)`. Fixed locally to `EventTypeCredentialChange`. Worth filing upstream.
