---
name: glitchdeck
description: Reproduce and regression-test HTTP, webhook, SSE, WebSocket, and gRPC failures using local YAML tapes and the built-in MCP server.
---

# Glitchdeck regression loop

Validate tapes without running them with `glitchdeck validate faults.tape.yaml`. Run a local tape with `glitchdeck test --json examples/checkout-dup-webhook.tape.yaml`, or wrap a command with `glitchdeck exec --tape faults.tape.yaml --json -- your-command`. The child receives `GLITCHDECK_PROXY_URL` and standard proxy environment variables. Version 1 test JSON is an array; version 2 and exec use an envelope. `--report` writes the envelope to a file.

Use `--tls-passthrough` or v2 `tls_passthrough` for pinned CONNECT hosts that should keep their upstream certificate; the upstream allowlist still applies.
Exec fails closed on `tls_rejected_only`, `egress_denied_only`, `zero_traffic`, or `zero_faults`; `--allow-zero-traffic` skips those checks but not tape expectations. To assert that a client rejects the interception CA, use `--allow-zero-traffic` with `expect.child_exit: nonzero`.
Go skips environment proxies for localhost; use reverse mode by setting the client base URL to `GLITCHDECK_PROXY_URL`.

For LLM streams, start with `examples/tapes/your-app-openai-sse-cut.tape.yaml` or its Anthropic counterpart.
Assert the application's `finish_reason` or `stop_reason`, not just that the SDK returned without an exception.
`expect.faults` with `min_applied: 1` fails if the fault did not fire; a non-zero `exec` alone is not proof it fired.
Use `dup-webhook` with `sequential`, `concurrent`, or `timeout_retry`; inspect `faults_triggered[].replays` for copy statuses and outcomes.
Set `ws-glitch` `frames: data` to count data frames and leave Close, Ping, and Pong untouched.

For piped tapes and CI reports, use `glitchdeck validate -` and `glitchdeck report --junit report.json`.

Inspect failed assertions and fault counts, fix the application, then rerun the same tape. Keep the tape in the repository as a regression test; the composite action supports exec mode with its `command` input. Exit 0 means pass; 1 means a mismatch; 2 means invalid input; 3 means runtime failure; 124 means timeout; 125–127 mean child startup failure.

The stdio server exposes 10 MCP tools. `exec_run` requires `glitchdeck mcp --allow-exec` and runs argv arrays, never shell strings, through a tape; its exec report includes `ok`, `child_exit`, `traffic`, `faults_triggered`, `diff`, and bounded `stdout`/`stderr`. Remote targets require server `--upstream-allow`.
`tape_export` emits v2 by default. Inspect `-32602` errors via `data.field` and `data.reason`; cancel a running job with `notifications/cancelled`.
