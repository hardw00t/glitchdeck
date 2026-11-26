# Glitchdeck

A local HTTP/1.1 and WebSocket fault proxy with a live oscilloscope and replayable YAML tapes. Break a checkout on purpose, see what went over the wire, and run the same scenario in CI.

## Run your first fault

Install from the checkout with Go 1.22 or newer:

```sh
go install ./cmd/glitchdeck
glitchdeck demo
```

Open [the console](http://127.0.0.1:8081), press **REC**, select **Double-Charge Webhook**, and click **Run Checkout**. The ledger records two $99.00 charges for one order. **STOP** freezes the tape; **EXPORT TAPE** downloads it. To see a ticker fail, arm **Silent WS Drop 1006** and click **Connect Ticker**.

Proxy your own local service instead:

```sh
glitchdeck proxy --target http://127.0.0.1:3000
```

The proxy listens at `127.0.0.1:8080`; the console defaults to `127.0.0.1:8081`. Change them with `--listen` and `--ui`, or change the built-in app listener with `demo --app`. Only loopback HTTP upstreams are supported. There is no TLS interception.

| Fault | Behavior |
| --- | --- |
| `tcp-rst` | TCP reset before headers or after a byte budget |
| `dup-webhook` | Replay the same request after a configured delay |
| `rate-limit` | Return a local 429 and `Retry-After` without calling upstream |
| `byte-trickle` | Stream in paced chunks with an optional one-time stall |
| `latency-wave` | Seeded sine, spike, or jitter delay before upstream |
| `ws-glitch` | Drop, delay, corrupt, truncate, or abnormally close selected frames |

## Run a tape in CI

```sh
glitchdeck test examples/clean.tape.yaml
glitchdeck test examples/checkout-dup-webhook.tape.yaml
```

The second command prints `duplicate_charges: expected 0, got 1`. A tape contains a seed, ordered rules, HTTP/WS actions and sleeps, and assertions on HTTP status, JSON paths, or latency. Exported demo tapes assert zero duplicate charges and a healthy ticker. The recorder keeps the latest 256 requests within an 8 MiB payload budget; it omits authorization and cookie headers. Review the tape before sharing it: bodies and URLs may contain sensitive data.

| Exit | Meaning |
| --- | --- |
| `0` | All assertions passed |
| `1` | An assertion failed; output includes the diff |
| `2` | Invalid configuration or runtime failure |

Use `--timeout`, `--target`, or `--json` to set the run deadline, override the tape's target, or emit structured results.

### Known limitations

- HTTP request and response trailers are not forwarded.
- Tape playback runs HTTP steps serially. It preserves sequence numbers and start offsets, but does not reproduce overlap between concurrent HTTP requests.
- Full WebSocket UTF-8 validation across fragments is not implemented. Recordings that cannot be replayed faithfully, including binary or fragmented WebSocket traffic and connections already open at **REC**, show a warning and exit `2` in CI.

## Console screenshots

- [Desktop: fault detonation](docs/screenshots/desktop-1440-demo-detonation.png)
- [Desktop: idle](docs/screenshots/desktop-1440-idle.png)
- [Mobile: fault rack](docs/screenshots/mobile-390-rack.png)
- [Mobile: demo and wire log](docs/screenshots/mobile-390-demo.png)
