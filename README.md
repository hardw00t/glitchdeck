# Glitchdeck

Glitchdeck is a local fault proxy with a live wire inspector and replayable YAML tapes. It handles HTTP/1.1, WebSocket, SSE, prior-knowledge h2c, TLS HTTP/2 and gRPC. Optional TLS interception uses a Glitchdeck CA you explicitly trust in the client.

![Glitchdeck console firing an LLM Stream Cut fault](docs/screenshots/v2-desktop-1440-llm-stream-cut.png)

## Install

On macOS or Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/hardw00t/glitchdeck/main/install.sh | sh
# Pin a release:
curl -fsSL https://raw.githubusercontent.com/hardw00t/glitchdeck/main/install.sh | GLITCHDECK_VERSION=v2.0.0 sh
```

On Windows, download and extract the matching `.zip` from [Releases](https://github.com/hardw00t/glitchdeck/releases).

With Go 1.26 or newer:

```sh
go install github.com/hardw00t/glitchdeck/cmd/glitchdeck@latest
```

## 15-second quickstart

Start the console:

```sh
glitchdeck demo
```

Open the [console](http://127.0.0.1:8081). Select **Double-Charge Webhook** and run a checkout, or select **LLM Stream Cut** and click **Stream Tokens**. To see a gRPC fault, arm **H2 / gRPC** and click **Run gRPC Call**. **REC → STOP → EXPORT TAPE** captures a replay of the traffic and rules. Review the tape before sharing it: authorization and cookie headers are removed, but request bodies and URLs can contain sensitive data.

In another terminal, from the repository root, replay a stream cut around a real client command (requires curl):

```sh
glitchdeck exec --tape examples/tapes/openai-sse-eof-before-done.tape.yaml --json -- sh -c '
  curl -q -fsSN -H "Content-Type: application/json" \
    -d "{\"tokens\":8,\"token_ms\":1}" "$GLITCHDECK_PROXY_URL/api/chat/stream"
'
```

The report shows the fault and a passing stream assertion. `exec` starts its own demo upstream, so this command also works without the console.

To proxy your own service:

```sh
glitchdeck proxy --target http://127.0.0.1:3000
```

The proxy and console default to `127.0.0.1:8080` and `127.0.0.1:8081`. Use `--listen` and `--ui` to choose other addresses. An explicit `--target` grants only its exact reverse-proxy origin. CONNECT, absolute-form requests, and tape replay need `--upstream-allow` (or `upstream_allow` in a tape) for non-loopback upstreams. Do not expose a TLS-intercepting listener to untrusted clients.

The console only accepts loopback peers, regardless of its bind address or the request's `Host`. Unless the proxy knows it is bound to loopback, it blocks upstream connections to loopback, link-local, and unspecified IPs even when reached through DNS. `--allow-loopback-egress` opts out of that restriction on trusted listeners; the upstream allowlist still applies.

Uploads stream upstream. Recording retains only a bounded body prefix and reports truncation; a matched fault that needs replay rejects bodies above its replay limit. Stop recording after upload requests finish to avoid an incomplete tape.

`glitchdeck demo` enables TLS interception by default. `glitchdeck ca init` creates a persistent CA; `glitchdeck ca print` prints only its public certificate. Use `--ca-dir` to select a store and `--upstream-ca` to trust a private upstream CA. Trust the interception CA only in the client under test. Prior-knowledge h2c is supported; the HTTP/1.1 `Upgrade: h2c` handshake is not. `--h2-tap=off` disables frame injection while retaining HTTP/2 relay.

Before passing `--ca-dir` to `glitchdeck demo`, initialize that directory with `glitchdeck ca init --ca-dir <dir>`. Without `--ca-dir`, the demo uses a temporary CA.

## Replay a tape

```sh
glitchdeck test --json examples/clean.tape.yaml
glitchdeck test examples/checkout-dup-webhook.tape.yaml
```

The checkout regression tape exits `1` and reports `duplicate_charges: expected 0, got 1`. [Example packs](examples/tapes/) show faults against the bundled demo and an OpenAI-compatible upstream. Version 1 tapes keep the original `test --json` array. Version 2 tapes and `exec --json` emit a versioned object with assertions and applied faults. `--report` saves that object to a file.

`exec` injects `GLITCHDECK_PROXY_URL`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and lowercase variants. The `NO_PROXY` list includes the proxy's own host and port. Point a client's base URL at `GLITCHDECK_PROXY_URL` to use reverse mode, including with Go clients that bypass environment proxies for loopback. `exec` sets `NODE_USE_ENV_PROXY=1` and, when TLS is enabled, provides temporary CA paths to supported clients. Proxy authentication is opt-in with `--proxy-auth`. macOS process cleanup covers the process group; detached descendants can escape. Windows cleanup is best-effort and does not guarantee stopping grandchildren.

`exec` exits `1` if no child requests reach the proxy, or if the tape enables fault rules but none apply to child traffic and the enabled rules do not all explicitly permit zero. Use `--allow-zero-traffic` to skip those two checks; explicit fault counts still apply to child traffic only. If traffic is missing, check proxy bypass and TLS CA trust. Client TLS handshake failures appear on stderr and in the wire log; `exec.tls_handshake_failure_count` counts them even if report details are omitted.

| Exit | Meaning |
| --- | --- |
| `0` | Expectations passed |
| `1` | Assertion, fault count, or child exit differed from expectations |
| `2` | Usage or invalid tape; also runtime failure for `test` |
| `3` | `exec` proxy, CA, or cleanup failure |
| `124` | Child timed out |
| `125` | Child could not start |
| `126` | Child command is not executable |
| `127` | Child command was not found |

## Real-world use cases

Run these from the repository root with the named local services running. Starter tapes contain no demo traffic; change paths and payloads to match your app. `glitchdeck validate examples/tapes/your-app-*.tape.yaml` checks them without running traffic.

### LLM stream disconnect

With an OpenAI-compatible streaming service on port 3000:

```sh
glitchdeck exec --tape examples/tapes/your-app-openai-sse-cut.tape.yaml --json -- sh -c '
  export OPENAI_BASE_URL="$GLITCHDECK_PROXY_URL/v1"
  curl -q -fsSN --max-time 5 -H "Content-Type: application/json" -d '\''{"model":"local","messages":[{"role":"user","content":"Hi"}],"stream":true}'\'' "$OPENAI_BASE_URL/chat/completions"'
```

For an Anthropic-compatible service on the same port:

```sh
glitchdeck exec --tape examples/tapes/your-app-anthropic-sse-cut.tape.yaml --json -- sh -c '
  export ANTHROPIC_BASE_URL="$GLITCHDECK_PROXY_URL"
  curl -q -fsSN --max-time 5 -H "Content-Type: application/json" -H "anthropic-version: 2023-06-01" -d '\''{"model":"local","max_tokens":32,"messages":[{"role":"user","content":"Hi"}],"stream":true}'\'' "$ANTHROPIC_BASE_URL/v1/messages"'
```

The tapes close before `[DONE]` or `message_stop`; a clean HTTP close can still make curl exit 0. For Python or Node SDKs, replace curl with your app command and use the exported base URL (or configure the SDK explicitly). Use a model and credentials accepted by your service.

### Duplicate Stripe webhook

Run against a local endpoint accepting this test payload; use a valid signed fixture if signature verification is enabled:

```sh
glitchdeck exec --tape examples/tapes/your-app-stripe-dup-webhook.tape.yaml --json -- sh -c '
  curl -q -fsS -H "Content-Type: application/json" -d '\''{"id":"evt_test_1","type":"payment_intent.succeeded"}'\'' "$GLITCHDECK_PROXY_URL/webhooks/stripe"'
```

The proxy replays the same POST; assert in your app's tests that the event produces only one charge or other side effect.

### WebSocket silent drop

With a server sending frames at `/ws`, use Node 22+ and inspect its abnormal close code:

```sh
glitchdeck exec --tape examples/tapes/your-app-ws-drop-1006.tape.yaml --timeout 10s --json -- node -e '
  const ws = new WebSocket(process.env.GLITCHDECK_PROXY_URL.replace(/^http/, "ws") + "/ws");
  ws.onclose = e => { console.log("close code:", e.code); process.exit(e.code === 1006 ? 0 : 1); };'
```

Change `after_frames` in the tape to choose when to drop the connection, then use your mobile client to test reconnect and backoff.

### gRPC deadline and HTTP/2 reset

For a local h2c service on port 3000 exposing the gRPC health service with reflection, install `grpcurl` and run:

```sh
glitchdeck exec --tape examples/tapes/your-app-grpc-deadline.tape.yaml --json -- sh -c '
  grpcurl -plaintext -d "{}" "${GLITCHDECK_PROXY_URL#http://}" grpc.health.v1.Health/Check'
```

The tape expects a nonzero child exit and an injected `DEADLINE_EXCEEDED`. For an h2c HTTP service exposing `/health`, use curl built with HTTP/2 support:

```sh
glitchdeck exec --tape examples/tapes/your-app-h2-reset.tape.yaml --json -- sh -c '
  curl -q -fsS --noproxy "*" --http2-prior-knowledge --max-time 5 "$GLITCHDECK_PROXY_URL/health"'
```

This injects `RST_STREAM` (`REFUSED_STREAM`); the tape expects curl to fail. Adjust the target and paths for your service. For a TLS upstream, use an `https://` target and `--upstream-ca` when its certificate is privately signed.

### Regression loop

1. Reproduce with `glitchdeck exec --tape examples/tapes/your-app-stripe-dup-webhook.tape.yaml --json -- your-test-command`, or use `glitchdeck mcp` to configure and inspect faults interactively.
2. Fix the app, then rerun the same tape and check the JSON fault counts and assertions.
3. Commit the `.tape.yaml` and run it in CI with the action below. See [SKILL.md](SKILL.md).

Configure the stdio server (the executable must be on `PATH`):

Claude Code, project `.mcp.json`:

```json
{"mcpServers":{"glitchdeck":{"type":"stdio","command":"glitchdeck","args":["mcp"]}}}
```

Cursor, project `.cursor/mcp.json`:

```json
{"mcpServers":{"glitchdeck":{"type":"stdio","command":"glitchdeck","args":["mcp"]}}}
```

Codex, `~/.codex/config.toml`:

```toml
[mcp_servers.glitchdeck]
command = "glitchdeck"
args = ["mcp"]
```

## Faults

| Fault | Behavior |
| --- | --- |
| `tcp-rst` | Reset the TCP connection before headers or after a byte budget |
| `dup-webhook` | Replay a request after a configured delay |
| `rate-limit` | Return an HTTP status and `Retry-After` without calling upstream |
| `byte-trickle` | Pace response chunks and optionally stall once |
| `latency-wave` | Add seeded sine, spike, or jitter delay |
| `ws-glitch` | Drop, delay, corrupt, truncate, or abnormally close frames |
| `sse-glitch` | Stall, drop events, truncate, corrupt JSON, or close before a terminator |
| `h2-glitch` | Send RST_STREAM or GOAWAY with a selected error code |
| `grpc-glitch` | Return an injected gRPC status before or after response messages |

## MCP and CI

Use the stdio configuration above for interactive MCP:

```sh
glitchdeck mcp
```

Use `proxy_start` with a loopback target or `demo`, `fault_set` to arm rules, and `wire_events` to inspect traffic. Use `tape_export` to save a recording, `tape_validate` to check a tape without running it, and `tape_run` to replay one. Tape input paths must stay within the MCP workdir (`.` by default). See [SKILL.md](SKILL.md) for the regression workflow.

Recordings strip common credential headers and replace sensitive query values with `REDACTED`. Check bodies and other fields for credentials before sharing a tape. Ring eviction sets `truncated` and `dropped_entries` in the exported tape and MCP result; the console download also exposes them as response headers.

Use `glitchdeck report --junit report.json` for CI test dashboards and `glitchdeck validate -` to lint tapes from stdin.

To run the [composite action](action.yml) from a checkout of this repository:

```yaml
- uses: actions/checkout@v4
- uses: ./
  with:
    tape: examples/clean.tape.yaml
    version: local
```

Wrap an application's tests in exec mode:

```yaml
- uses: hardw00t/glitchdeck@v2
  with:
    tape: examples/tapes/your-app-stripe-dup-webhook.tape.yaml
    target: http://127.0.0.1:3000
    command: pytest tests/test_webhooks.py
```

In another repository, pin a release tag (or the floating major tag):

```yaml
- uses: actions/checkout@v4
- uses: hardw00t/glitchdeck@v2
  with:
    tape: tapes/checkout.tape.yaml
```

For a published action ref, omit `version` to use that ref. The action uses verified release binaries when available for the requested release, with a Go build for source refs. It exposes `exit-code` and the JSON `report` path.

## Console screenshots

- [Desktop: v2 default](docs/screenshots/v2-desktop-1440-default.png)
- [Desktop: LLM stream cut](docs/screenshots/v2-desktop-1440-llm-stream-cut.png)
- [Desktop: H2/gRPC fault](docs/screenshots/v2-desktop-1440-h2-grpc-fault.png)
- [Mobile: fault rack](docs/screenshots/v2-mobile-390-rack.png)
- [Mobile: LLM demo](docs/screenshots/v2-mobile-390-demo-llm.png)
- [v0 desktop](docs/screenshots/desktop-1440-idle.png) · [v0 mobile](docs/screenshots/mobile-390-rack.png)
