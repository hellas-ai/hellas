# Caller-signed HTTPS Fetch

The `http` environment signs raw HTTP metadata and bytes, allowing OpenAI,
Anthropic, Google, Kimi or another API without adding a vendor to the app.
It does not translate request schemas: supply the upstream's own JSON or binary
body, encoded as standard padded base64.

```json
{
  "url": "https://api.example.com/v1/messages",
  "method": "POST",
  "headers": [["content-type", "application/json"]],
  "body_base64": "e30=",
  "tls": {
    "roots": {"mode": "web_pki"},
    "spki_sha256": []
  },
  "max_response_bytes": 262144
}
```

`body_base64` above is `{}`; replace it with your actual API request. Header
names are lowercase. Requests contain no provider credential selector. The
response ceiling is at most 8 MiB.
All final HTTP statuses, including errors and redirects, are returned to the
client as signed responses; they are never logged with their bodies. Redirects
are not followed. A transport failure or an oversized response is not a
successful paid result, and is never retried automatically.

`roots.mode` is either `web_pki` (bundled public trust roots) or `certificates`
with `der_base64`, a nonempty array of exact DER trust anchors. System roots
are not silently added. Hostname, certificate validity, chain signatures and
TLS handshake signatures are always checked. `spki_sha256` is an optional
array of lowercase 64-digit SHA-256 hashes of the leaf certificate's DER SPKI;
at least one must match when supplied. Pins add constraints to chain validation.
Provider credentials require the exact trust roots configured by the operator;
a caller cannot substitute different roots.

The operator configures credential scopes separately:

```json
{
  "allowed_hosts": [],
  "allow_private_addresses": false,
  "credentials": [
    {
      "allowed_origins": ["https://api.example.com"],
      "allowed_paths": ["/v1/messages"],
      "allowed_methods": ["POST"],
      "header_name": "authorization",
      "secret_env": "ACCOUNT_ONE_API_KEY",
      "prefix": "Bearer "
    },
    {
      "allowed_origins": ["https://api.example.com"],
      "allowed_paths": ["/v1/embeddings"],
      "allowed_methods": ["POST"],
      "header_name": "x-api-key",
      "secret_env": "ACCOUNT_TWO_API_KEY",
      "prefix": ""
    }
  ]
}
```

The provider selects the credential whose declared origin, path and method cover
this request. Owner, paid and granted Fetch use the same selection. A request
outside every declared scope runs anonymously. Overlapping scopes in one backend
are rejected at configuration; two accounts covering the same request need two
backends. TLS roots and header names cannot disambiguate overlapping scopes.
A public resource's `account_backed` consent flag must agree with whether any of
its allowed requests intersects a credential scope; a mismatch is rejected.
Automatically generated model resources set this flag from their backend scopes.
Secrets are read from the provider process's environment and held in
memory. Alternatively, replace `secret_env` with `secret_file` and `secret_field`
to read a private JSON login file on each request. The loader rejects symlinks,
non-regular files, files that are not owner-only, and files over 64 KiB; atomic
token rotation is picked up without restarting the provider.
`secret_field` and `expires_field` accept a top-level key or a JSON Pointer
starting with `/`, for example `/tokens/access_token` or `/claudeAiOauth/accessToken`.
This lets the provider read native login files directly. The native login tool
still owns token refresh; do not independently rotate a CLI's refresh token.

For short-lived tokens, a file credential can include:

```json
{
  "secret_file": "/private/account.json",
  "secret_field": "access_token",
  "refresh": {
    "expires_field": "expires_at",
    "command": ["/absolute/path/to/account-tool", "refresh"]
  }
}
```

`expires_at` is Unix time in seconds. The trusted operator command runs when
expiry is within 30 seconds, with no customer data or captured output. Refreshes
are serialized per account, have a 30 second timeout, and must replace the file
with a renewed token. Failures impose a cooldown. The account's login tool owns
OAuth and refresh-token persistence; Hellas does not interpret vendor logins.

Resolved secrets are injected only for an exact authorized origin, path and method,
with the operator's configured roots (public WebPKI by default). Callers cannot
override that account's header or
change trust roots to impersonate its origin. Restrict paths to the inference
endpoints the account is intended to expose. Path restrictions do not cover
query strings: if an API selects models or pricing through query parameters,
a caller can still steer cost within an allowed path.

DNS answers are resolved and checked on every request. Connections are reused
only for the same origin, DNS address set and TLS roots/pins.
Each provider retains at most 32 client pools, with at most four idle connections
per origin and a 90 second idle expiry. Credentials are still resolved per request;
the pools contain no default authorization headers. Private,
loopback, link-local, multicast and other special-purpose addresses are denied
by default. An operator can explicitly enable private addresses only with a
nonempty exact host allowlist, for controlled private services. Environment
proxies, redirects, transparent decompression and request retries are disabled.

In Gate, select **HTTPS (caller selects URL)** and paste this operator config
into **HTTPS accounts and egress**. `{}` enables public HTTPS without provider
accounts. In the CLI's Fetch route file, use:

```json
{
  "service": "http",
  "method": "request",
  "destination": {"type": "http", "config": {"credentials": []}}
}
```

The route file wraps entries in `routes`. Work payment channels authorize jobs
and charge their fixed price; grants authorize jobs within their allowances.
For CLI paid requests, `hellas fetch URL --contract http --pay 20 --provider
ENROLLMENT_ID@NODE_ID` runs under the named contract; a quote that does not
admit it is refused. `--save-job DIR` writes a reusable
[job folder](../../docs/jobs.md) for `hellas transact --job DIR`.

Results contain one `Adaptor.Http.Head` event followed by base64 body events
and a signed terminal. Hop-by-hop and framing headers (`connection`,
`transfer-encoding` and `content-length`) describe the provider's own
connection, so they are not part of the signed head; the body bytes are the
only length truth. `HttpFetchResponse::from_output` reconstructs the body
and checks ordering and size after transcript signature verification.

## Provider-owned credential demonstration

Generic HTTPS preserves provider-side API-key injection. The buyer signs the
HTTP request. The provider matches its declared credential scopes and inserts
the selected secret header immediately before sending HTTPS.
The key is absent from the buyer input transcript and normal response transcript. Credentialed requests require the operator's configured
trust roots, an exact permitted origin/path/method,
and no caller override of the credential header. Redirects are not followed.
Scope credentials to upstreams you trust: an upstream receives the header and could
include it in its response; a transparent proxy cannot promise to hide a secret
that the upstream itself returns.

Run the offline TLS demonstration from the Hellas checkout:

```sh
nix develop --command cargo test -p hellas-providers provider_injects_secret -- --nocapture
```

It runs the production HTTP provider and adaptor against a local TLS server,
checks that the server receives the key, verifies the signed input and output,
and confirms neither transcript contains the key. It also checks that warmed
connection pools cannot bypass credential scope or header-override checks. The
fixture configures its CA as the operator credential's trust root; a buyer
substitution of those roots is refused.
