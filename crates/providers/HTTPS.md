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
  "credential": "account-1",
  "max_response_bytes": 262144
}
```

`body_base64` above is `{}`; replace it with your actual API request. Header
names are lowercase. `credential` may be omitted for unauthenticated requests
or caller-owned authorization headers. The response ceiling is at most 8 MiB.
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
A caller-supplied trust anchor does not qualify for provider-owned credentials.

The operator configures account aliases separately:

```json
{
  "allowed_hosts": [],
  "allow_private_addresses": false,
  "credentials": {
    "account-1": {
      "allowed_origins": ["https://api.example.com"],
      "allowed_paths": ["/v1/messages"],
      "allowed_methods": ["POST"],
      "header_name": "authorization",
      "secret_env": "ACCOUNT_ONE_API_KEY",
      "prefix": "Bearer "
    },
    "account-2": {
      "allowed_origins": ["https://api.example.com"],
      "allowed_paths": ["/v1/messages"],
      "allowed_methods": ["POST"],
      "header_name": "x-api-key",
      "secret_env": "ACCOUNT_TWO_API_KEY",
      "prefix": ""
    }
  }
}
```

Aliases select independent accounts, including several accounts at the same
origin. Secrets are read from the provider process's environment and held in
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
with public WebPKI roots. Callers cannot override that account's header or
change trust roots to impersonate its origin. Restrict paths to the inference
endpoints the account is intended to expose.

DNS answers are checked and pinned to the request's connection. Private,
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
  "destination": {"type": "http", "config": {"credentials": {}}}
}
```

The normal route file still needs its `routes` and `callers` envelope. Paid
channels use their payment policy for admission; Courtesy callers use explicit
route grants. On Gate's Run page, `http` is accepted as the execution environment.
For CLI paid requests, `paid-work prepare-fetch --execution-environment http`
prints the manifest ID to put in the work config.

Results contain one `Adaptor.Http.Head` event followed by base64 body events
and a signed terminal. `HttpFetchResponse::from_output` reconstructs the body
and checks ordering and size after transcript signature verification.
