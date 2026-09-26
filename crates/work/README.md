# Paid Fetch and provider payload retention

Paid Fetch shares the existing channel authorization, execution gate, delivery,
payment certificate, and settlement flow with Evaluate. A Fetch channel selects
`PaidWorkPolicy::Fetch`; the policy commits to its route and manifest as well
as its fixed price and input/output limits. Evaluate's canonical records and
version-1 close descriptors remain unchanged. Fetch close descriptors use
version 2.

## Provider storage

The Fetch profile requires `Retention::Ephemeral` and a metadata-only provider
journal. Channel mounting selects that journal automatically; binding a Fetch
provider to an ordinary payload journal fails. Live requests and responses are
fully verified before their accounting records are committed.

The journal persists authorizations, signatures, request/result digests, running
and delivery markers, payment certificates, ledger state, and close state.
It omits prepared requests and output transcripts from both append records and
rotation checkpoints. Those bodies exist in memory while the job is active.
The paid executor invokes the configured Fetch route directly, without passing
through Courtesy's transcript store or replay cache. Upstream and projection
faults are reduced to fixed error messages before they reach the paid-work
driver's logs.

Fetch channels open metadata-only journals on both endpoints: a client
restart cannot reconstruct a lost request or replay a received response,
though a delivered result's retained evidence still settles payment.
This policy covers application-managed storage; it does not establish the
upstream API's retention policy or replace host memory/swap/crash-dump
controls.

## Restart behavior

| Provider state before restart | Recovery |
| --- | --- |
| Accepted, not dispatched | Input is gone; do not dispatch automatically |
| Running | Outcome is indeterminate; do not invoke again |
| Result recorded | Signed result metadata survives; response body cannot be delivered or replayed |
| Already delivered | Client can still submit its signed payment; duplicate submissions are idempotent |
| Paid | Payment and settlement recovery continue from durable metadata |

Existing deadline and close rules still apply to jobs whose bodies were lost.
Provider failure is not turned into a paid result. The client must not assume
that retrying delivery after a provider restart can recover its response.

The journal header distinguishes payload journals from metadata-only journals.
Opening one as the other fails. This change does not migrate or erase old files.

## CLI

Build the CLI with `node,llm`. Use `paid-work prepare-fetch` to create a
client-owned signed request:

```sh
hellas-cli paid-work prepare-fetch \
  --service openai --method responses \
  --execution-environment openai-responses \
  --payload-file request.json --out paid-fetch.bin
```

Use the same local identity when preparing the input and running
`paid-work run --prepared-input paid-fetch.bin`. The existing run command
handles setup, acceptance, delivery, authenticated payment, and optional
settlement; it still needs its existing provider/funding/config arguments.

In the work config, replace `policies.execution` with `policies.fetch` (exactly
one is allowed):

```json
{
  "allowed_environment": "<64 hex digits of the Fetch manifest ID>",
  "service": "openai",
  "method": "responses",
  "max_request_body_bytes": 4096,
  "max_output_events": 64,
  "max_output_bytes": 16384,
  "max_spool_bytes": 65536,
  "max_encoded_result_frame": 65536,
  "max_encoded_prepared_input": 65536,
  "dispatch_margin_blocks": 4,
  "delivery_margin_blocks": 2,
  "oracle_grace_blocks": 6,
  "fixed_price": 10
}
```

The route must also exist in the provider's Fetch route configuration.
Route-wide capabilities and shared Fetch concurrency limits remain enforced.
Courtesy's caller quota policy is not the paid admission policy; a paid channel
authorizes its own work.

## Generic HTTPS and App Attest

`FetchEnvironment::Http` interprets the caller-signed HTTPS request described
in [the HTTPS guide](../providers/HTTPS.md). The body binds the full URL,
method, headers, binary request body, TLS roots, additional SPKI pins, account
alias, and response-size ceiling. The result signs HTTP status, headers and
exact response bytes. No upstream vendor needs to be compiled into Gate.

To sell this interpreter, use its manifest ID as `allowed_environment` and
replace `service`/`method` in `policies.fetch` with:

```json
"open_fetch": {
  "require_spki_pin": false,
  "allowed_hosts": []
}
```

An empty list permits any public host, subject to the operator's independently
configured egress restrictions. A nonempty list matches exact host names.
The host and required-pin conditions are checked before paid acceptance.
The HTTPS driver enforces certificate validation and address restrictions at
connection time. A registered route such as `http/request` must implement the
HTTP manifest. The paid policy's byte/frame limits must cover the encoded HTTP
response as well as its envelopes (base64 expands binary bodies).

Use `paid-work prepare-fetch --execution-environment http` for this request.
Add `--assurance apple-app-attest` when targeting Gate. On `paid-work run`,
provide `--provider-genesis`, `--apple-app-id` and `--apple-cd-hashes`. Each paid
Work and WorkSetup connection verifies a fresh Open proof before sending its
request. The proof binds the TLS exporter, nonce, service ALPN, enrollment and
producer key; the producer must also be the payment channel's provider.
Result verification takes the assurance from the client's signed input and
rejects a weaker output scheme.

## Application interface

`hellas-sdk` is the application boundary for both CLI and signed hosts:

- `paid_client::PaidWorkSession` owns one funded channel. It authenticates the
  provider, resumes journaled jobs, verifies results, pays, and closes. The CLI
  and paid gateway use this same session. `run_paid_work` wraps one complete job.
- `PreparedPaidWorkInput` and `PaidWorkPolicy` select Evaluate or Fetch. Each
  profile validates its own canonical input, bounds and terminal result; the
  payment lifecycle does not interpret HTTP or model output.
- `FetchProviderOptions` and `start_fetch_provider` take an operator's route
  registry, enrollment and root prover. The host owns its identity and credentials;
  the SDK supplies the shared provider routing and finalized-chain clock.
- `HttpFetchRequest` and `HttpFetchResponse` express HTTPS semantics. The Fetch
  backend executes an admitted request; canonical transcript verification checks
  its result under the assurance requested by the caller.

A session serializes its jobs. After cancellation, recover the journal before
admitting another job. Evaluate supports authenticated incremental token delivery;
Fetch currently returns a complete bounded response. Fetch journals are
metadata-only on both endpoints; Evaluate client journals may retain payloads.

Apple App Attest requires a provisioned, signed macOS host. `ProducerSigned`
verifies the key and transcript but does not attest the binary. These are the
implemented assurance choices, checked explicitly before request disclosure and
again during result verification.

Adding Open changed the Work and WorkSetup service schema IDs. Existing paid
method IDs and canonical payment encodings are unchanged; use matching updated
client and provider builds.

Tests inspect provider journal files after each commit and rotation, reopen
them after simulated process loss, verify payment recovery without bodies,
and cover both signed result schemes. Local TLS tests exercise roots, pins,
wrong hostnames, redirects, address restrictions and response bounds. Portable
App Attest tests cover connection/service binding and replay counters. They do
not contact a paid upstream or enroll a real Apple device.
