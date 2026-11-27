---
name: glitchdeck
description: Reproduce and regression-test HTTP, webhook, SSE, WebSocket, and gRPC failures using local YAML tapes and the built-in MCP server.
---

# Glitchdeck regression loop

Validate tapes without running them with `glitchdeck validate faults.tape.yaml`. Run a local tape with `glitchdeck test --json examples/checkout-dup-webhook.tape.yaml`, or wrap a command with `glitchdeck exec --tape faults.tape.yaml --json -- your-command`. The child receives `GLITCHDECK_PROXY_URL` and standard proxy environment variables. Version 1 test JSON is an array; version 2 and exec use an envelope. `--report` writes the envelope to a file.

Exec fails with exit 1 if no requests reach the proxy, or if enabled fault rules trigger no faults without an explicit zero-allowing fault expectation. `--allow-zero-traffic` disables both checks; other assertions and child-exit expectations still apply. Check proxy bypass and CA trust when traffic is missing.

For LLM streams, start with `examples/tapes/your-app-openai-sse-cut.tape.yaml` or its Anthropic counterpart.
Assert the application's `finish_reason` or `stop_reason`, not just that the SDK returned without an exception.
`expect.faults` with `min_applied: 1` fails if the fault did not fire; a non-zero `exec` alone is not proof it fired.

For piped tapes and CI reports, use `glitchdeck validate -` and `glitchdeck report --junit report.json`.

Inspect failed assertions and fault counts, fix the application, then rerun the same tape. Keep the tape in the repository as a regression test; the composite action supports exec mode with its `command` input. Exit 0 means pass; 1 means a mismatch; 2 means invalid input; 3 means runtime failure; 124 means timeout; 125–127 mean child startup failure.

For interactive use, configure the local stdio server as `{"command":"glitchdeck","args":["mcp"]}`. Start with `proxy_start`, configure rules with `fault_set`, inspect `wire_events`, then use `tape_export`, `tape_validate`, and `tape_run`. Finish with `proxy_stop`. Use controlled loopback targets only.
