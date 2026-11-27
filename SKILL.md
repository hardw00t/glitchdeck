---
name: glitchdeck
description: Reproduce and regression-test HTTP, webhook, SSE, WebSocket, and gRPC failures using local YAML tapes and the built-in MCP server.
---

# Glitchdeck regression loop

Run a local tape with `glitchdeck test --json examples/checkout-dup-webhook.tape.yaml`, or wrap a command with `glitchdeck exec --tape faults.tape.yaml --json -- your-command`. The child receives `GLITCHDECK_PROXY_URL` and standard proxy environment variables. Version 1 test JSON is an array; version 2 and exec use an envelope. `--report` writes the envelope to a file.

Inspect failed assertions and fault counts, fix the application, then rerun the same tape. Keep the tape in the repository as a regression test. Exit 0 means pass; 1 means a mismatch; 2 means invalid input; 3 means runtime failure; 124 means timeout; 125–127 mean child startup failure.

For interactive use in Claude Code, Codex, or Cursor, configure the local stdio server as `{"command":"glitchdeck","args":["mcp"]}`. Start with `proxy_start`, configure rules with `fault_set`, inspect `wire_events`, then use `tape_export` and `tape_run`. Finish with `proxy_stop`. Use controlled loopback targets only.
