# Demo CAEP Push Receiver

Companion to [`../transmitter`](../transmitter). Builds an SSF receiver via the
[`ssfreceiver`](../ssfreceiver) library, registers a push stream with the
mock transmitter, listens on `/events`, and pretty-prints every SET it gets.

## Run (with the mock transmitter)

```bash
# terminal 1
cd ../transmitter && go run ./...

# terminal 2
cd ../receiver && go run ./...
```

Then open <http://localhost:8080/> and click **Push event**. The receiver's
terminal will print the parsed event.

## Flags

- `-transmitter URL` — transmitter metadata URL (default `http://localhost:8080/.well-known/ssf-configuration`)
- `-receiver URL` — externally reachable base URL of this receiver (default `http://localhost:9000`); used as the `endpoint_url` registered with the transmitter
- `-listen ADDR` — interface to bind on (default `:9000`)
- `-token TOKEN` — bearer token to send to the transmitter (default `demo-token`)
- `-verify-set` — verify SET signatures against the transmitter's JWKS, plus `iss`/`aud` claims. Off by default to keep the demo turn-key; turn it on to demo real validation.

## What it demonstrates

- Stream registration via `builder.Setup()` — issues `POST /ssf/streams` and stores the returned stream config.
- Push delivery — the transmitter `POST`s SETs to `/events` with `Content-Type: application/secevent+jwt`.
- Per-event-type dispatch on `secEvent.Event.Type()`, including the SSF verification event.
- Optional signature + claim verification (`-verify-set`).
