# HTTP APIs through Fetch

`gateway --http-fetch-config FILE` exposes exact HTTP routes over the generic
HTTPS Fetch environment. Request and response bodies keep the upstream format,
including SSE, tool calls and non-2xx errors. It requires a provider trust anchor
and a provider route with a caller grant; it does not use the token-native paid
pool. See [provider account and egress configuration](../crates/providers/HTTPS.md).

Example gateway configuration for Kimi Code:

```json
{
  "service": "https",
  "method": "request",
  "max_in_flight": 2,
  "routes": [{
    "path": "/v1/chat/completions",
    "method": "POST",
    "url": "https://api.kimi.com/coding/v1/chat/completions",
    "credential": "kimi"
  }]
}
```

The service and method must match the provider's configured Fetch route. The
credential alias belongs to that provider. Each alias shares a concurrency
limit and cooldown across its HTTP routes. Paths and methods match exactly;
query parameters retain their order, repeats and percent encoding. Ordinary
client headers, including idempotency keys and vendor extensions, pass through.
Connection-specific headers, credentials, cookies and gateway control headers
are removed; the caller's gateway bearer never becomes an upstream credential. Optional
`headers` holds operator-supplied `[name, value]` pairs, with lowercase names.
Configured values override the corresponding client header. The former
`forward_headers` whitelist has been removed.

Several accounts at one upstream can use distinct aliases and gateway paths,
such as `/kimi-a/v1/chat/completions` and `/kimi-b/v1/chat/completions`, both
mapped to the upstream's chat endpoint. The client's base URL selects the route.
Each alias has independent admission and cooldown; routes sharing an alias
share those limits. This gateway targets one Hellas provider node. It does not
automatically select accounts, fail over between them or route using quota data.

Omit `credential` for an unauthenticated upstream. Such routes share admission
by origin. Optional `tls` uses the [Fetch TLS vocabulary](../crates/providers/HTTPS.md)
for exact trust anchors and pins, defaulting to WebPKI. Custom roots cannot be
combined with a provider credential; that restriction remains enforced by the
provider. Private destinations also require its explicit egress opt-in.

```sh
hellas-cli --identity ./gateway.identity gateway \
  --http-fetch-config ./http-gateway.json \
  --provider "$PROVIDER_ENROLLMENT" \
  --node-id "$PROVIDER_NODE_ID" --node-addr "$PROVIDER_ADDRESS" \
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

## Archives and ZDR

CLI gateways archive authenticated requests and responses by default under
`~/.hellas/gateway-archive`, or `--archive-dir DIRECTORY`. This applies to the
existing inference routes as well as HTTP Fetch. Each exchange has owner-only
`request.bin`, `response.bin` and `metadata.json` files. Metadata records status,
size, content type/encoding, elapsed time, completion and trace context; it excludes authentication
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
to 32,768 events and 16 MiB of signed payload. The provider has a 20 minute total
HTTP deadline and a 90 second response idle timeout. Exceeding a stream limit
closes it as incomplete. A slow response consumer applies bounded backpressure,
with a 90 second drain timeout. QUIC cancellation stops an idle upstream without
waiting for its next byte. Individual upstream deliveries are forwarded promptly,
split at 16 KiB; the provider does not wait for a full buffer.

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
