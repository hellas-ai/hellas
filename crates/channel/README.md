# Paid Fetch and provider payload retention

Paid Fetch shares the existing channel authorization, execution gate, delivery,
payment certificate, and settlement flow with Compute. A Fetch channel's
`InvocationPolicy` admits Fetch; the admission commits to its route, contract and
resource limits. Separate `JobPaymentPolicyV2` terms bind the price and block margins.
Both profiles use version-3 close descriptors and journal format 7. Older
journals are refused; close old devnet channels with the old binary first.

Canonical paid-work and grant records, prepared inputs, and usage accounting live in
`hellas_channel::model` and `hellas_authority::model`. RPC owns generated messages and signed-transcript codecs.

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
through a separate transcript store or replay cache. Upstream and projection
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
Opening one as the other fails.

## CLI

Use a [job folder](../../docs/jobs.md) to keep the caller input reusable:

```sh
hellas-cli --passkey owner.key transact --job ./job --provider NODE_ID -o ./result
hellas-cli --faucet fetch https://example.com/data --provider NODE_ID --payment 20 \
  --spki-sha256 LEAF_SPKI_SHA256 --save-job ./request -o ./response
hellas-cli --passkey owner.key transact --settle --provider NODE_ID
```

The helper selects the Fetch contract from the authenticated provider quote and
calls the same transaction as a raw folder. The provider's owner-approved
`PaidPolicy` fixes its contract, route, price and resource limits. Chain
configuration holds chain pins and journal locations. See the
[paid gateway guide](../../docs/paid-gateway.md) for provider and wallet setup.

The route must also exist in the provider's Fetch route configuration.
Route-wide capabilities and shared Fetch concurrency limits remain enforced.
The mounted Work channel authorizes its jobs.

## Generic HTTPS and App Attest

The HTTP Fetch contract interprets the caller-signed HTTPS request described
in [the HTTPS guide](../providers/HTTPS.md). The body binds the full URL,
method, headers, binary request body, TLS roots, additional SPKI pins, account
alias, and response-size ceiling. The result signs HTTP status, headers and
exact response bytes. No upstream vendor needs to be compiled into Gate.

To sell this interpreter, its manifest is the paid policy's
`allowed_environment`; its route policy can use:

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

Use `hellas fetch --contract http-contract.json` to select the quoted canonical
HTTP descriptor explicitly. Software providers require the selected endpoint identity. Apple-attested
providers also require an independently approved `--trust-store` and `--trust-policy`
with app IDs and release CDHashes; see the [paid gateway guide](../../docs/paid-gateway.md).
The signed offer carries the provider enrollment and channel policy. Every paid
Work and WorkSetup connection verifies a fresh Open proof before sending its
request. The proof binds the TLS exporter, nonce, service ALPN, enrollment and
producer key; the producer must also be the payment channel's provider.
Result verification takes the assurance from the client's signed input and
rejects a weaker output scheme.

## Application interface

`hellas-sdk` is the application boundary for both CLI and signed hosts:

- `paid_client::PaidWorkSession` owns one funded channel. It authenticates the
  provider, resumes journaled jobs, verifies results, pays, and closes. The CLI
  and paid gateway use this same session. `hellas_sdk::transact` executes folders and helper-built jobs.
- `grant_client::GrantSession` owns a private grant channel and its proposal
  journal. Both session types use `WorkLink` for authenticated transport and the
  common Work policy and transcript verification code. Grant Responses startup
  lives in `grant_gateway::responses`; `gateway` always names `hellas-gateway`.
- `PreparedInvocation` and `InvocationPolicy` select Compute or Fetch. Each
  profile validates its own canonical input, bounds and terminal result; the
  payment lifecycle does not interpret HTTP or model output.
- `FetchProviderOptions` and `start_fetch_provider` take an operator's route
  registry, enrollment and root prover. The host owns its identity and credentials;
  the SDK validates resources before opening journals and builds a `WorkRouter`
  for grants, payment channels, or both. `GrantProviderOptions` supplies available
  resource policies and job bounds. Only payment channels start a chain observer.
- `HttpFetchRequest` and `HttpFetchResponse` express HTTPS semantics. The Fetch
  backend executes an admitted request; canonical transcript verification checks
  its result under the assurance requested by the caller.

The native host SDK composes both funding modes in one build; funding is explicit
runtime configuration. Consumers needing only the underlying grant protocol or
ledger can use `hellas-rpc` and `hellas-channel` and `hellas-authority` without a chain runtime.

Both funding paths reserve a `WorkPermit` before entering the executor queue.
`AdmittedWork` carries that permit into `RunningWork`, which owns it until the
physical invocation ends. Grant acceptance reserves capacity before co-signing;
payment obligations wait for capacity. Grant execution and gateway tasks are
joined at shutdown, including after a journal failure. Provider and gateway
shutdown return errors after cleanup, so callers must handle the result.

A session serializes its jobs. After cancellation, recover the journal before
admitting another job. Evaluate supports authenticated incremental token delivery;
Fetch currently returns a complete bounded response. Fetch journals are
metadata-only on both endpoints; Evaluate client journals may retain payloads.

Apple App Attest requires a provisioned, signed macOS host. `ProducerSigned`
verifies the key and transcript but does not attest the binary. These are the
implemented assurance choices, checked explicitly before request disclosure and
again during result verification.

Tests inspect provider journal files after each commit and rotation, reopen
them after simulated process loss, verify payment recovery without bodies,
and cover both signed result schemes. Local TLS tests exercise roots, pins,
wrong hostnames, redirects, address restrictions and response bounds. Portable
App Attest tests cover connection/service binding and replay counters. They do
not contact a paid upstream or enroll a real Apple device.

Work uses journal format 7 and close descriptor v3. Each request selects its
funding kind and channel ID; setup requests select their bond. One peer may own
several bonds.

The grant definition format no longer includes scheduling `weight`. Offers and
journals written with that field are incompatible with this format; retain those
journals for explicit migration instead of deleting them or resetting allowances.
