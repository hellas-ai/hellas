# HTTP APIs through Fetch

`gateway --http-fetch-config FILE --paid-work-config POOL` exposes exact HTTP
routes over paid HTTPS Fetch. Request and response bodies keep the upstream
format, including SSE, tool calls and non-2xx errors. Every request uses a funded
channel from the [paid pool](paid-gateway.md); missing payment configuration is a
startup error. See [provider account and egress configuration](../crates/providers/HTTPS.md).

The gateway's standard API paths can serve several accounts or provider nodes.
It reads the requested model, finds backends configured to serve that model and
route, and keeps an existing session on its assigned backend. Model names and
request/response bodies are forwarded unchanged.

Example with two Kimi accounts behind one endpoint:

```json
{
  "service": "https",
  "method": "request",
  "max_in_flight": 2,
  "backends": {
    "kimi-a": {
      "models": ["k3"],
      "credential": "kimi-a",
      "routes": [{
        "path": "/v1/chat/completions",
        "method": "POST",
        "url": "https://api.kimi.com/coding/v1/chat/completions"
      }]
    },
    "kimi-b": {
      "models": ["k3"],
      "credential": "kimi-b",
      "routes": [{
        "path": "/v1/chat/completions",
        "method": "POST",
        "url": "https://api.kimi.com/coding/v1/chat/completions"
      }]
    }
  }
}
```

Both accounts use the same client base URL, such as `http://127.0.0.1:8080/v1`.
Add backends with their exact supported models and API routes for other accounts.
The configured service and method must match the provider's Fetch route. An
optional backend `max_in_flight` overrides the global per-account limit. Routes
sharing a credential alias on the same provider share capacity and cooldown;
duplicating that alias does not multiply its allowance.

A backend's optional `provider` is an endpoint ID from the paid pool. It may be
omitted only when the pool contains exactly one provider for the HTTP Fetch
manifest. Addresses, funding, journals and enrollment/Apple trust pins belong in
the pool. The provider must mount a paid Fetch channel for the gateway's transport
and settlement identities and expose the configured service/method.

The gateway bearer authorizes access to the gateway's payment identity. The
router selects an account, then the paid client signs the exact Fetch request
and proposes it on that provider's channel. The provider checks the funded edge,
credit, deadlines, signature and Fetch policy before durably accepting work;
only that accepted job can invoke the upstream. The credential's origin, path
and method restrictions remain enforced by the provider. Courtesy caller grants
do not authorize this HTTP path.

Signed response prefixes stream as they arrive. Successful HTTP completion
follows verification of the complete result and the provider's durable payment
acknowledgement. Each accepted valid terminal costs the channel's agreed fixed
price, including HTTP error statuses. Already available prefixes share bounded
wire frames, with a local observer-readiness check before each frame and individual
signature checks for every event. Batching does not wait for more upstream data.
Requests are not retried on another
provider after account selection. The pool serializes work within each provider
channel; concurrent requests assigned to that provider queue within its deadline, including requests for different
accounts on that provider. Separate providers have independent channels.

Paths and methods match exactly; query parameters retain their order, repeats
and percent encoding. Ordinary client headers, including idempotency keys and
vendor extensions, pass through. Connection-specific headers, credentials,
cookies and gateway control headers are removed; the caller's gateway bearer
never becomes an upstream credential. Optional route `headers` holds operator
`[name, value]` pairs, with lowercase names. Configured values override the
corresponding client header. Account credentials belong on the backend.

For opaque HTTP passthrough without model selection, configure top-level `routes`
instead of `backends`.

Omit `credential` for an unauthenticated upstream. Such routes share admission
by origin. Optional `tls` uses the [Fetch TLS vocabulary](../crates/providers/HTTPS.md)
for exact trust anchors and pins, defaulting to WebPKI. Custom roots cannot be
combined with a provider credential; that restriction remains enforced by the
provider. Private destinations also require its explicit egress opt-in.

```sh
hellas-cli --identity ./gateway.identity gateway \
  --http-fetch-config ./http-gateway.json \
  --paid-work-config /srv/hellas/paid-pool.json \
  --port 8080 --bearer-token-file ./gateway.bearer
```

The client signs the request and verifies each response chunk before forwarding
it. Provider-owned credentials require public WebPKI roots. The gateway asks the
provider for ephemeral retention and disables inference replay. Its own archive
policy is independent of provider retention and upstream `store` fields.

For Kimi Code, set `KIMI_MODEL_NAME` to an available model and use `--wrap kimi`;
the wrapper supplies `KIMI_MODEL_BASE_URL` and `KIMI_MODEL_API_KEY`. A separately
launched client can use the same variables and the private gateway bearer file.
Choose a context size that fits the byte limits below.

## Model selection and session affinity

New sessions use an eligible account outside cooldown with available capacity.
The gateway chooses the least occupied account, rotating ties. Existing sessions
stay pinned even when that account becomes busy or rate-limited: they receive a
retry response; new sessions can use another account. A request is sent once.
Neither a transport failure nor an upstream error causes automatic replay on a
different backend. A transport failure briefly excludes that backend from new
sessions. Quota polling remains monitoring; selection uses configured model
capabilities, current capacity and observed response cooldowns, not estimates
from token usage or external quota scrapes.

Affinity recognizes `x-hellas-session-id`, Claude Code's
`x-claude-code-session-id`, Codex's `session-id`/`thread-id`, Claude's session ID
in `metadata.user_id`, and `prompt_cache_key` (used by Kimi Code), in that order.
An explicit session survives changes of client connection. Without one, requests
for the same model/API on the same accepted HTTP connection stay together.
Connection-only bindings are reclaimed once that connection closes. Different
explicit sessions may share that connection. Affinity is scoped by
model and API family; Responses compaction and Messages token counting share
their generation API's family.

Responses API IDs observed in JSON or SSE bind `previous_response_id` and
`conversation` continuations to the original backend, including continuations
that omit the model. Unknown, expired or
conflicting state returns 409 before contacting an upstream. Session identifiers
are held as salted hashes in a bounded memory table (16,384 entries, 24 hours
idle). Unexpired entries are not evicted to admit new sessions; a full table
returns 503. Restarting the gateway clears affinity. Server-side continuations
whose mapping was lost require full context rather than being sent to a guessed
account. Full-history requests can establish new affinity after a restart.

Model routing reads JSON, gzip or zstd requests with an 8 MiB decoded limit and
an 8 MiB zstd window limit. It forwards the original encoded bytes. An unsupported
model receives 404; malformed or unsupported routing input receives 400. These
checks precede upstream execution. Model-less, empty-body auxiliary requests use
an eligible backend; account-specific quota endpoints are not aggregated.

## Archives and ZDR

Fetch payment journals on both endpoints retain hashes, signatures and accounting
records, with payloads held in memory. After a restart they can re-send an existing
payment certificate, but cannot reconstruct or replay a lost request/response.
Unpaid work with a lost payload keeps its channel reserved until its payment
deadline; it is never re-executed from a new request. Existing payload-bearing
Fetch journals are refused instead of silently changing their retention policy.
The HTTP archive below is the gateway's separate payload persistence policy.

CLI gateways archive authenticated requests and responses by default under
`~/.hellas/gateway-archive`, or `--archive-dir DIRECTORY`. This applies to the
existing inference routes as well as HTTP Fetch. Each exchange has owner-only
`request.bin`, `response.bin` and `metadata.json` files. Metadata records status,
size, content type/encoding, elapsed time, completion, selected backend and trace context; it excludes authentication
headers. `x-hellas-request-id` identifies the exchange. Failed or cancelled
streams retain an incomplete archive. Archiving is best-effort: failures during
setup, request/response writes or finalization are reported without replacing
the upstream status or interrupting its response. After a write fails, archiving
stops for that exchange; the next ordinary request attempts a fresh archive.
Once an archive has been created, `x-hellas-request-id` remains present even if
saving its response metadata fails. It identifies an archive attempt, not a
guarantee of a complete durable record. There is no automatic archive pruning.

Archive failures emit a `hellas_archive` warning with the operation, I/O error
kind and OS error code, without payloads, credentials, paths or raw error text.
With `otel`, `hellas.gateway.archive.failures` counts failures by `archive.stage`
(`prepare`, `request`, `response_head`, `response_body`, `finish`) and `error.type`.
The Prometheus name is `hellas_gateway_archive_failures_total`. Successful HTTP
responses remain successful in request telemetry even when their archive fails;
monitor the archive counter separately. ZDR requests do not attempt archival or
increment this counter.

`x-hellas-zdr: true` disables application payload persistence for that request.
`--zdr` enforces this for all requests. Ambiguous flags, `store: true`, and ZDR
with inference caching enabled are rejected before archive writes. A non-ZDR
request may be archived even when its upstream `store` is false. Unauthorized,
invalid ZDR requests and bodies exceeding the 2 MiB ingress limit are rejected
without payload archives. Non-ZDR requests that pass ingress but exceed the
smaller Fetch envelope limit are archived with their 413 response.

These switches govern this gateway's application writes. They do not establish
OS swap/dump protection, a remote provider's host policy, upstream retention,
or the coding client's own session-log policy. Software identities do not
attest those properties. The embedded Responses-only `start_fetch` API retains
its host-managed storage policy.

## Limits and telemetry

HTTP input is limited to 1,523,712 bytes, reserving envelope space inside the
2 MiB signed Fetch request. Responses are limited to 8 MiB and the Fetch stream
to 32,768 events and 16 MiB of signed payload. The paid policy can impose tighter
limits; its transcript spool is capped at 32 MiB. Configure the spool and output
budgets for the encoded HTTP response (including base64 and signed envelopes).
Each wire frame remains bounded independently: Fetch completion authenticates
all preceding prefixes without packing the full response back into one frame.

The provider has a 20 minute total HTTP deadline and a 90 second response idle
timeout. The pool's `timeout_secs` and on-chain block deadlines must also fit the
expected execution time. Exceeding a stream limit closes it as incomplete.
Individual upstream deliveries are forwarded promptly, split at 16 KiB.
Before proposal, a disconnect cancels the request. After proposal, collection and
payment continue independently of the HTTP reader. The bounded HTTP output queue
reports an error to a stalled reader without stopping settlement; graceful
shutdown drains accepted operations. Unfinished operations retain their accounting
evidence for recovery, subject to Fetch's in-memory payload lifetime.

No generation is automatically retried upstream. Upstream status and end-to-end
response headers reach the client, including Location, ETag, `Retry-After`,
request IDs and rate limits. Hop-by-hop headers and cookies are removed. Body
framing is regenerated; representation Content-Length is retained for HEAD/304.
A 429, or a 5xx carrying `Retry-After`, starts a shared account cooldown;
delta seconds and HTTP dates are accepted. Requests during cooldown receive
the status that established the longest remaining delay: a 503 remains a 503,
so clients can keep retrying overloads. Missing or invalid delays on a 429 use one second. Excess
concurrency returns 503 with `Retry-After: 1`.

With `otel`, traces connect HTTP ingress, Fetch RPCs, credential refresh and
upstream HTTP. Span attributes exclude request/response bodies and credentials.
`hellas.backend` and `gen_ai.request.model` identify configured backend/model
choices in request metrics and traces; `hellas.routing.affinity` records the
selection reason in traces. Raw session IDs are not exported.
Outbound trace context replaces the caller's propagation headers instead of
appending duplicates. Upstream response `traceparent` and `tracestate` are
preserved; `x-hellas-trace-id` identifies the gateway's trace independently.
Pooled QUIC connections have separate root spans so their lifetime cannot delay
exporting the first request's trace.
`hellas.gateway.http.requests`, `.duration`, `.time_to_first_byte` and `.tokens`
record status, completion, timings and standard OpenAI/Anthropic usage fields.
SSE usage is recognized even when the upstream omits Content-Type. Cache reads
and writes are reported separately as `cache_read` and `cache_write` token kinds;
the input/output counts retain the upstream's meaning. Usage is unknown when
upstream omits it.
Bodies remain encoded on the wire and in archives. Usage observation accepts
plain JSON/SSE and gzip, with a 32 MiB decoded-byte budget and a 512 KiB pending
JSON/line budget. Invalid compression, unsupported encodings or exceeded budgets
leave usage unknown without affecting delivery.
Account quota windows still come from the upstream quota exporter. Request
token totals alone cannot determine subscription quota or billing.

This is an HTTP API bridge with explicit routes, authentication and resource
limits. It does not implement CONNECT, WebSocket upgrades, streaming uploads,
HTTP trailers or automatic rewriting of redirect URLs. Clients using Responses
WebSockets must select their HTTP/SSE transport. Archive I/O remains on the
response path, although its errors no longer fail requests. These are contract
differences from a general transparent HTTP proxy, even when inference and
tool-call payloads are preserved exactly.
