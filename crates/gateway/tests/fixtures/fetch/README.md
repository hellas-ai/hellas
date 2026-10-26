# Fetch SSE fixtures

Recorded from the gateway at H1 head `dbb6bd3d`, before changing `WorkBackend`.
The tests exercise the production Fetch request adapter and SSE response body
with deterministic upstream semantic events. They pin rendering metadata to
`resp-fixture`, `msg-fixture`, and Unix time `1700000000`; no bytes are normalized
or JSON-reserialized for comparison.

- `text.sse`: two text deltas, including Unicode and a newline, then usage and completion.
- `tool.sse`: a function call with split Unicode JSON arguments, then usage and completion.
- `limited.sse`: reasoning, partial output, usage, and a maximum-output terminal.

The request bodies and upstream events are in `src/fetch_gateway/tests.rs`.
Signed Fetch delivery and admission are covered by the Work and SDK suites;
these fixtures record the gateway's presentation bytes.
