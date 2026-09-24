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
    "credential": "kimi",
    "forward_headers": ["content-type", "accept", "user-agent"]
  }]
}
```

The service and method must match the provider's configured Fetch route. The
credential alias belongs to that provider. Each alias shares a concurrency
limit and cooldown across its HTTP routes. Paths and methods match exactly;
query parameters are rejected. The forward list only accepts protocol headers;
the caller's gateway bearer never becomes an upstream credential. Optional
`headers` holds operator-supplied `[name, value]` pairs, with lowercase names.

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
size, elapsed time, completion and trace context; it excludes authentication
headers. `x-hellas-request-id` identifies the exchange. Failed or cancelled
streams retain an incomplete archive. The gateway refuses requests when it
cannot open their archive, and stops streaming on an archive write failure.
There is no automatic archive pruning.

`x-hellas-zdr: true` disables application payload persistence for that request.
`--zdr` enforces this for all requests. Ambiguous flags, `store: true`, and ZDR
with inference caching enabled are rejected before archive writes. A non-ZDR
request may be archived even when its upstream `store` is false. Unauthorized,
oversized and invalid ZDR requests are rejected without payload archives.

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
closes it as incomplete. Individual upstream deliveries are forwarded promptly,
split at 16 KiB; the provider does not wait for a full buffer.

No generation is automatically retried upstream. Upstream status, `Retry-After`,
request IDs and rate-limit headers reach the client. A 429, or a 5xx carrying
`Retry-After`, starts a shared account cooldown; delta seconds and HTTP dates
are accepted. Missing or invalid delays on a 429 use one second. Excess
concurrency returns 503 with `Retry-After: 1`.

With `otel`, traces connect HTTP ingress, Fetch RPCs, credential refresh and
upstream HTTP. Span attributes exclude request/response bodies and credentials.
`hellas.gateway.http.requests`, `.duration`, `.time_to_first_byte` and `.tokens`
record status, completion, timings and standard OpenAI/Anthropic usage fields.
Usage is unknown when upstream omits it; cached tokens are reported separately.
Account quota windows still come from the upstream quota exporter. Request
token totals alone cannot determine subscription quota or billing.
