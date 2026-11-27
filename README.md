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

The console only accepts loopback peers, regardless of its bind address or the request's `Host`. Unless the proxy knows it is bound to loopback, it blocks upstream connections to loopback, link-local, and unspecified IPs even when reached through DNS. The exact origin of an explicit `--target` stays reachable, so `--listen 0.0.0.0:8080 --target http://127.0.0.1:3000` still serves devices on your network. `--allow-loopback-egress` opts out of that restriction on trusted listeners; the upstream allowlist still applies.

Uploads stream upstream. Recording retains only a bounded body prefix and reports truncation; a matched fault that needs replay rejects bodies above its replay limit. Stop recording after upload requests finish to avoid an incomplete tape.

`glitchdeck demo` enables TLS interception by default. `glitchdeck ca init` creates a persistent CA; `glitchdeck ca print` prints only its public certificate. Use `--ca-dir` to select a store and `--upstream-ca` to trust a private upstream CA. Trust the interception CA only in the client under test. Prior-knowledge h2c is supported; the HTTP/1.1 `Upgrade: h2c` handshake is not. `--h2-tap=off` disables frame injection while retaining HTTP/2 relay.

Use repeatable `--tls-passthrough` flags or the v2 tape key `tls_passthrough` for pinned hosts: exact hosts, `*.suffix` (subdomains only, not the apex), or `host:port`, matched on the CONNECT authority, not SNI. Passthrough still needs `--upstream-allow` for non-loopback upstreams and never bypasses the SSRF or egress checks.

Before passing `--ca-dir` to `glitchdeck demo`, initialize that directory with `glitchdeck ca init --ca-dir <dir>`. Without `--ca-dir`, the demo uses a temporary CA.

## Replay a tape

```sh
glitchdeck test --json examples/clean.tape.yaml
glitchdeck test examples/checkout-dup-webhook.tape.yaml
```

The checkout regression tape exits `1` and reports `duplicate_charges: expected 0, got 1`. [Example packs](examples/tapes/) show faults against the bundled demo and an OpenAI-compatible upstream. Version 1 tapes keep the original `test --json` array. Version 2 tapes and `exec --json` emit a versioned object with assertions and applied faults. `--report` saves that object to a file.

`exec` injects `GLITCHDECK_PROXY_URL`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and lowercase proxy variants. Both `NO_PROXY` cases receive the same deduplicated list: inherited entries are kept unless they would bypass the target (dropped with a warning), `--no-proxy` entries are kept verbatim, and the listener address is included. Passthrough is not added to `NO_PROXY`: the connection still goes through glitchdeck. Use `GLITCHDECK_PROXY_URL` as the client base URL for reverse mode, including with Go clients that skip environment proxies for loopback.

`exec` sets `NODE_USE_ENV_PROXY=1`. With TLS enabled, it merges inherited `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `NODE_EXTRA_CA_CERTS` certificates into the temporary CA bundle. It sets `GLITCHDECK_CA_CERT` to the interception CA, `NODE_EXTRA_CA_CERTS` to the inherited Node roots plus that CA, and `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`, `AWS_CA_BUNDLE`, [`DENO_CERT`](https://docs.deno.com/runtime/reference/env_variables/#special-environment-variables), [`GIT_SSL_CAINFO`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpsslCAInfo), [`PIP_CERT`](https://pip.pypa.io/en/stable/topics/https-certificates/#using-a-specific-certificate-store), [`NPM_CONFIG_CAFILE`](https://docs.npmjs.com/cli/v11/using-npm/config/#cafile), and [`CARGO_HTTP_CAINFO`](https://doc.rust-lang.org/cargo/reference/config.html#httpcainfo) to the merged bundle. Java needs a JVM truststore; .NET on Linux can use the OpenSSL bundle, while macOS and Windows use the OS trust store.

Proxy authentication is opt-in with `--proxy-auth`. macOS process cleanup covers the process group; detached descendants can escape. Windows cleanup is best-effort and does not guarantee stopping grandchildren.

`exec` exits `1` for TLS-rejected-only traffic (`tls_rejected_only`), upstream-allowlist-denied-only traffic (`egress_denied_only`), no requests (`zero_traffic`), or enabled fault rules that never apply and do not all explicitly permit zero (`zero_faults`). `--allow-zero-traffic` skips all four checks; explicit fault and child-exit expectations still apply. `exec.traffic` reports CONNECT and inner-request counts, successful interception and tunnel counts, TLS rejections, egress denials, and dial failures. TLS handshake failures appear on stderr and in the wire log; `exec.tls_handshake_failure_count` counts them even if report details are omitted.

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

These tapes close cleanly after three events. **Your SDK may not raise:** in [loopback SDK tests](docs/v2.2.0.md), OpenAI returned `"tok0 tok1 tok2"` with `error: null`, and Anthropic returned `stop_reason: null`. Assert a successful `finish_reason` or `stop_reason` in your application; a clean HTTP close can make curl exit 0. The tape's `min_applied: 1` expectation fails if the fault did not fire. A non-zero `exec` can have other causes and is not proof it fired. For Python or Node SDKs, replace curl with your app command and use the exported base URL (or configure the SDK explicitly). Use a model and credentials accepted by your service.

| Stream fault or parameter | Use |
| --- | --- |
| `eof_early`, `after_events` | Cut cleanly after a chosen number of events |
| `inject_error`, `provider` | Inject a provider-shaped midstream error |
| `corrupt_tool_args`, `mode` | Break streamed tool arguments while retaining valid outer JSON |
| `corrupt_tool_args`, `then` | Continue, close cleanly, or reset after corruption |
| `done_events` | Add custom terminal event names |
| `rate-limit`, `provider`, `burst` | Return provider-shaped limits for the first matching requests |

Tool argument corruption re-marshals JSON, so object key order may change; compare normalized JSON. Gemini `functionCall.args` is an object, not streamed argument strings, and is not corrupted (`no_tool_args`). Matched gzip and deflate SSE streams are decoded and sent as identity; unsupported encodings such as br pass through unchanged and skip the SSE fault.

### Stripe/webhook idempotency

Run against a local endpoint accepting this test payload; use a valid signed fixture if signature verification is enabled:

```sh
glitchdeck exec --tape examples/tapes/your-app-stripe-concurrent-race.tape.yaml --json -- sh -c '
  curl -q -sS -w "\nOriginal HTTP %{http_code}\n" -H "Content-Type: application/json" -d '\''{"id":"evt_test_1","type":"payment_intent.succeeded"}'\'' "$GLITCHDECK_PROXY_URL/webhooks/stripe"'
```

- **Concurrent delivery:** `mode: concurrent` starts the original and four copies together. Use it to test whether a check-then-insert handler can process the same event twice.
- **Commit then retry:** switch to `examples/tapes/your-app-stripe-timeout-retry.tape.yaml` to observe the injected `504`. The original reaches the receiver before the timeout response; the same event is then retried.
- **Read the original status, copy histogram, and database together:** `faults_triggered[].replays.status` counts copy responses and `outcomes` groups their results. The original can receive `409` if a copy inserts first. Across all five deliveries, five `200`s and five rows means duplicate processing; one `200` and four `409`s, or five `200`s and one row, means deduplication.

### WebSocket silent drop

With a server sending frames at `/ws`, use Node 22+ and inspect its abnormal close code:

```sh
glitchdeck exec --tape examples/tapes/your-app-ws-drop-1006.tape.yaml --timeout 10s --json -- node -e '
  const ws = new WebSocket(process.env.GLITCHDECK_PROXY_URL.replace(/^http/, "ws") + "/ws");
  ws.onclose = e => { console.log("close code:", e.code); process.exit(e.code === 1006 ? 0 : 1); };'
```

Set `frames: data` and choose `after_frames` to count data frames without touching Close, Ping, or Pong; `all` remains the default. For a frame-drop example, see `examples/tapes/your-app-ws-data-drop.tape.yaml`. Oversized frames get Close `1009` (4 MiB limit) and malformed frames get Close `1002`; both appear in `ws_frame` events and reports. An intentional `close_1006` still simulates a silent disconnect.

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
{"mcpServers":{"glitchdeck":{"type":"stdio","command":"glitchdeck","args":["mcp","--allow-exec"]}}}
```

Cursor, project `.cursor/mcp.json`:

```json
{"mcpServers":{"glitchdeck":{"type":"stdio","command":"glitchdeck","args":["mcp","--allow-exec"]}}}
```

Codex, `~/.codex/config.toml`:

```toml
[mcp_servers.glitchdeck]
command = "glitchdeck"
args = ["mcp", "--allow-exec"]
```

These examples opt in to command execution; omit `--allow-exec` to leave it disabled.

## Faults

| Fault | Behavior |
| --- | --- |
| `tcp-rst` | Reset the TCP connection before headers or after a byte budget |
| `dup-webhook` | Replay a buffered request in staggered (`sequential`), simultaneous (`concurrent`), or commit-then-retry (`timeout_retry`) mode |
| `rate-limit` | Return a status and `Retry-After`; `provider`, `retry_after_ms`, `reset_sec`, and `burst` add provider envelopes and retry-storm behavior |
| `byte-trickle` | Pace response chunks and optionally stall once |
| `latency-wave` | Add seeded sine, spike, or jitter delay |
| `ws-glitch` | Drop, delay, corrupt, truncate, or abnormally close `data`, `control`, or `all` frames |
| `sse-glitch` | Stall, drop, truncate, corrupt JSON or tool arguments (`corrupt_tool_args`), inject provider errors (`inject_error`), or close before a terminator; `done_events` adds custom terminal names |
| `h2-glitch` | Send RST_STREAM or GOAWAY with a selected error code |
| `grpc-glitch` | Return an injected gRPC status before or after response messages |

## MCP and CI

Use the stdio configuration above for interactive MCP:

```sh
glitchdeck mcp
```

The ten tools are `proxy_start`, `proxy_stop`, `fault_set`, `fault_clear`, `wire_events`, `demo_trigger`, `tape_export`, `tape_validate`, `tape_run`, and `exec_run`. Use `proxy_start` with a loopback target or `demo`, `fault_set` to arm rules, and `wire_events` to inspect traffic. Tape input paths must stay within the MCP workdir (`.` by default). See [SKILL.md](SKILL.md) for the regression workflow.

`--allow-exec` grants the MCP client arbitrary command execution as the server user, the same as giving it a shell. The workdir and egress policy confine **glitchdeck's own** file access and proxy, but they are **not** a sandbox for the child. The child can read any file and open direct sockets. Clients that already have a shell (Claude Code, Cursor, Codex) lose nothing by enabling it. Clients that don't must not get it silently.

`exec_run` takes an argv array, not a shell command string; inspect `ok` in its report for assertion failures. Remote targets require the server's `--upstream-allow`; an MCP call can never widen `--upstream-allow`. The `cwd` is resolved within the workdir, but a writable symlink can be swapped between validation and process start (TOCTOU). Windows process cleanup is best-effort and does not guarantee stopping grandchildren.

`tape_export` emits v2 by default; request `format: "v1"` for a compatible recording. Incomplete exports report `replayable: false`.

Recordings strip common credential headers and `Referer`, and redact sensitive query values, including ambiguous semicolon-separated suffixes. Check bodies and other fields for credentials before sharing a tape. Ring eviction sets `truncated` and `dropped_entries`; MCP also reports `omitted_body_bytes` when it shortens bodies to fit the 64 KiB inline or 1 MiB file export limit. Recordings that omit bodies or trailers are incomplete and cannot be replayed.

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
