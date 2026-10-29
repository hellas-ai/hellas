# Paid gateway

`hellas --passkey owner.key gateway --paid-work-config /srv/hellas/pool.json
--text-model qwen3.gguf` renders each text request as a Compute job, sends it
to the configured providers and pays through their real funded work channels.
Each provider has its own endpoint identity, bond, payment funding, and client
journals. The gateway skips busy provider channels and serializes requests
within each channel. Providers must already hold the GGUF named by the job (for
example via `hellas store adopt`); the gateway never uploads the weights.

With `--http-fetch-config`, the same pool carries HTTP Fetch requests. Its paid
policy must select the HTTP Fetch manifest and a matching Fetch route policy;
see [HTTP routing](http-gateway.md). The HTTP router chooses the provider and
account, so this path never falls back to a different provider or funding source.

The provider keeps its paid policy in its node authority. A provider started
with `serve --paid-work-config FILE` has its selected owner (`--passkey`,
`--faucet` or `--faucet-account N`) approve exactly that file's terms at
startup, unless the authority already holds them, and delegate the stake its
offers bond. Paid work is sold only with this file; nothing has a built-in
default. [`faucet-provider.toml`](examples/faucet-provider.toml) is a complete
example: price, jobs per channel, channel credit, offer bounds, upload/output
limits, maximum steps, the execution limit, `compute = true` and an optional
`[fetch]` section. `--faucet` selects only the owner key from the public
devnet faucet allocation; it never sets price or limits. Restarts with the same
file change nothing. A lower stake cap is refused before changing policy if no
already-delegated coin fits it; use the explicit owner `chain delegate --split`
path to reshape unused stake first. The saved `admin.json` profile beside the
provider identity works with the passkey administration commands.

An owner can also set the policy with `hellas admin work
policy-command.json`, using a `SetPaidPolicy` command with `expected_revision`
and `policy`. A stale revision or a daily node-key session cannot change it.

Execution limits are A's: a job over the upload limit is refused before it
runs, and a job that exceeds `execution_timeout_ms` is killed with its worker
process group and is not paid. Catena jobs run in a separate worker process;
that isolation is crash/timeout containment, not a sandbox, and there is no
memory metering. Before paying, the gateway checks that each result is signed
by the provider and matches this job; Hellas does not re-run it.

Compute terms should allow at least 4 MiB of upload for Whisper. The faucet
example uses `max_upload_bytes = 4194304`; provider and grant limits are explicit
terms, with no implicit runtime default. Whisper ships roughly 0.47–0.85 MB of
rendered program, 960,000 bytes of log-mel features, and three F32 vocabulary
masks (622,380 bytes for a 51,865-token model). The allowance also covers input
metadata. The client includes the program with every job; a provider may deduplicate
received sources by content ID, but never needs a preinstalled model program.
Weights remain a separate ordinary content-addressed asset.


The pool selects providers and expected prices. It obtains each policy with
`RequestOffer`; it does not copy the provider's policy or name a prebuilt bond:

```json
{
  "providers": [
    {
      "chain_config": "/srv/hellas/chain.json",
      "journal_root": "/var/lib/hellas-gateway/provider-a",
      "provider": "PROVIDER_ENDPOINT_ID",
      "provider_addrs": ["192.0.2.10:31145"],
      "payment": 20
    }
  ],
  "acceptance_blocks": 16,
  "terminal_blocks": 64,
  "payment_blocks": 32,
  "timeout_secs": 300,
  "max_pending_requests": 64
}
```

`chain_config` contains the chain cross-check, six validator URLs, journal root,
`poll_ms` and optional `max_observation_age_ms`. It contains no paid policies or
client routes. The requester and gateway start no chain node. They authenticate
remote state against independently configured genesis and consensus pins; relay
URLs supply transport only. `transact` defaults to the embedded devnet trust
and `wss://devnet.hellas.ai/ws/validator-{0..5}`. Local transport and settlement
keys are created on first use and retained with the identity.

Use `--passkey owner.key`, `--faucet`, or `--faucet-account N` for channel funding.
A new channel asks for one owner approval over its exact quoted amount: the
provider's jobs per channel times its price, plus omission reserve and fees.
At most four eligible owner coins fund one delegated output; change returns
undelegated to the same owner. The wallet records the signed reshape before
submission and shares reservations across gateway providers. Later jobs reuse
the open channel. `transact --settle --provider NODE_ID` closes it and returns unspent funding.

A request without funding coins returns a quote and writes no paid journal. The
quote states the canonical channel policy, omission collateral and exact funding.
A funded request proves live coins owned by the client's principal and delegated
to its settlement key. Their sum must match the quote exactly. The provider
reserves its own owner-delegated stake within `max_stake_per_client` and
`max_open_offers`, and creates one live offer per client principal and key.
The original signed offer, policy and authenticated peer are durable together;
retries return the same offer and restart requires no route configuration.
Unanswered offers expire at their bond timeout.

ProducerSigned providers need only the selected endpoint ID. Each live Open
checks that the enrollment names that transport and verifies the producer proof.
Apple-attested providers additionally require the existing independent trust store.
For those entries, add a top-level `trust_store` directory and a per-provider
`trust_policy` ID. Approve app IDs and release CDHashes independently:

```sh
hellas trust --store /var/lib/hellas-gateway/trust approve provider-a \
  --expected-revision 0 --policy /srv/hellas/provider-a-trust.json \
  --reason 'Reviewed Apple application and release hashes'
```

The existing trust JSON contains `provider_genesis`, `assurance`, and `apple`
with `app_id` and `cd_hashes`. Missing or mismatched
Apple approval fails before funding or disclosure. Approval replacement retains
its revision checks and persistent assertion counters. `transact` accepts
`--trust-store` and `--trust-policy` for Apple providers; software providers do not
need them. Grant gateways keep their existing independent approval requirements.

Owners delegate or reclaim coins through the global passkey:

```sh
hellas --passkey owner.key chain delegate --rpc ws://127.0.0.1:8788 \
  --trust ./chain-trust.json --network devnet --node NODE_SETTLEMENT_KEY \
  --coin COIN_ID --split 12
hellas --passkey owner.key chain sweep --rpc ws://127.0.0.1:8788 \
  --trust ./chain-trust.json --network devnet --coin COIN_ID
```

`--split VALUE` creates up to three delegated coins of that value and returns the
remainder undelegated to the owner. The node cannot authorize that owner action.
`--node` uses base58 settlement keys; coin IDs are hex. Returned provider stake
stays delegated by default; `offers.redelegate_payout = false` keeps it with the
owner without delegation. Client payouts remain delegated to their own node.

The omission bond must exceed the payment capacity. At price 20 and ten jobs,
a capacity of 200 and omission collateral of 201 require 401 units with zero fees
and reserve. The client checks
this before signing setup terms or creating a journal.
The provider verifies the gateway owner's delegated funding and retains the
first authenticated peer with its offer. All participants must use the same
compatible chain revision.

Each text job fixes the rendered program, the GGUF weights, the prompt tokens
and the token budget (`max_tokens`, else `--default-max-tokens`). The
provider's step loop feeds each emitted token back until that budget, within
its policy's `max_steps`. The payment terms fix the price per job. Model
presentation (the Qwen3 chat template and function tools) lives in the shared
`hellas-presentation` adapter, usable by clients and the gateway.

The provider reserves delivery credit before streaming signed output prefixes.
The gateway verifies each prefix as it arrives, then authenticates and journals
the complete result and obtains the provider's durable payment acknowledgement
before reporting completion. One open subscription replaces repeated result
polls. Payment is an accumulating channel certificate. An established, healthy
channel performs no validator RPCs on its request or streaming paths. Requests
use local credit checks, signatures and journal commits. Channels settle through
the existing close protocol; the pool does not automatically refill them.

Each channel observes finalized history independently of its requests. The client
has one request owner and a separate observer handle, so a slow response cannot
block close monitoring or reorder payment exchanges. The provider also drives
channels independently: one stalled channel cannot block another's recovery.
Applying a close and crediting a certificate use the same short journal lock.
Jobs within a channel still finish in order, including collection and payment
after an HTTP client disconnects. A server that keeps an HTTP response open after
an application completion event therefore holds that channel until EOF. The
generic HTTP route preserves those trailing bytes. Separate funded channels
execute independently; `paid.queue` measures time waiting for a channel.

The work configuration accepts `max_observation_age_ms` (default 5000), which
must exceed `poll_ms`. Admission, delivery and new certificates stop when the
observer fails or no new verified finalized height arrives within that age.
Repeated reads of an old tip do not renew it. The bound starts before the chain
read, not after it finishes, and readiness is published only after all intervening
blocks have been applied. Results may still be retained during an observation
outage; existing payment certificates remain safe to retransmit. Because renewal
requires an *advancing* finalized height, this age should also exceed the
deployment's block interval by a comfortable margin: a chain finalizing slower
than the age spends every gap stale, and admission flaps on each block.

This is an online channel: its observer must detect unilateral closes and submit
any response within `omit_response_blocks`. Configure observation age, network
recovery and submission latency to fit that window at the deployment's block
rate. The local age limit cannot guarantee recovery through a partition longer
than the on-chain response window. Setup and restart catch-up may wait on
validators; ordinary requests do not perform that work.

Keep gateway and provider identities and journals across service restarts,
including when the operating system's store is ephemeral. Startup recovers
retained Compute jobs and re-sends payment certificates idempotently. Fetch
journals omit bodies. A verified delivery recorded before a crash is paid from
its retained evidence, even when the payload is gone. Jobs without either payload
or verified delivery retain their credit reservation until the payment deadline;
recovery skips them and never submits them anew. Disconnecting an
HTTP client cancels work that has not yet been proposed. Once a signed proposal
may have reached a provider, collection and payment continue despite disconnects.
The pool admits at most `max_pending_requests` queued or running requests (default
64); additional requests receive HTTP 503 and may be retried. `timeout_secs`
bounds queueing, recovery, provider fallback, execution and payment together,
rather than restarting for each provider. Text requests skip busy provider
channels; each connection attempt gets at most 10 seconds before trying another
route within that shared budget. The HTTP paid route uses this same
configured budget; non-paid routes retain their existing 3600-second default. HTTP delivery has an
8 MiB byte budget (including event overhead), allowing retained-result bursts.
A consumer that exhausts it receives a stream error; its accepted work continues
settlement without waiting for HTTP backpressure.

SIGTERM and wrapped-command failures drain outstanding operations. Set the service
stop timeout above `timeout_secs`. An operation that reaches its deadline retains
its journal for recovery, as does abrupt process termination.

For systemd, set `--gateway-profile /var/lib/hellas-gateway/gateway-profile.json`.
Provision the [HTTP authority and scoped credential](admin.md#http-gateway-authority)
first. Startup opens that authority and never creates a token or administrator.
Every request checks current credential and grant rights. Non-loopback listeners
also require `--allow-remote`; use a trusted network or a TLS reverse proxy.

The NixOS options are `services.hellas.gateway.paidWorkConfig`,
`paidWorkJournalRoots` (writable client journals), `gatewayProfile`, and
`authorityJournal` when the authority journal is outside the managed state directory.


## Request traces

Build with the opt-in `otel` feature and set `OTEL_EXPORTER_OTLP_ENDPOINT`
to the collector's HTTP base URL on clients, gateways, providers and validators.
The SDK appends `/v1/traces` and `/v1/metrics`; signal-specific endpoint variables
accept complete URLs instead. Give these services distinct `OTEL_SERVICE_NAME`
values. Validators require both `validator` and `otel`. Sampling honors the
upstream sampled flag; `OTEL_TRACES_SAMPLER=parentbased_traceidratio` with
`OTEL_TRACES_SAMPLER_ARG` controls new root traces. Default packages omit the
Hellas telemetry exporters; transitive dependencies still include metrics and SDK
crates. Nix module `otel` options select enabled builds.

The gateway accepts W3C `traceparent`/`tracestate` headers and returns
`traceparent` plus `x-hellas-trace-id` for trace lookup. Without an incoming
context it starts a new trace. HTTP spans remain alive while SSE is being
consumed; paid tasks retain their parent after an HTTP disconnect. Generic
Hellas RPC metadata carries the context over both Iroh and WebSocket mux
connections, including validator queries and submissions. Transparent frame
relays preserve this metadata. The explorer relay continues the context through
its forwarding span, and proof-origin HTTP queries continue the caller trace.
Background chain observation uses separate `paid.channel.observe` traces.

Useful spans include `http.server`, `paid.gateway`, `paid.queue`,
`paid.executor.stream`, GenAI `chat MODEL` and `text_completion` operations,
and RPC spans named for their full service/method. RPC method and status are
attributes. GenAI spans report first-chunk latency and token counts;
HTTP spans report first body delivery, status, byte
count and completion. Spans do not contain prompts, token values, authorization
headers or tool data. Log events stay in the log sink and are excluded from
the OTLP span exporter.

An instrumented HTTP client should inject its active context on every request.
For a manual correlation check, send a fresh valid W3C `traceparent` header and
look up its 32-character trace ID in Jaeger. Reusing one fixed header across
unrelated requests combines those requests into one trace and should be avoided.

### End-to-end check traces

The VM checks under `hydraJobs.x86_64-linux.e2e` use telemetry-enabled test
packages and a local collector. Each check publishes
`traces/<machine>/traces.jsonl` as a Hydra build product, with collector
diagnostics alongside it. The files contain newline-delimited
[OTLP JSON exports](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/fileexporter)
and can be imported through the collector's `otlpjsonfile` receiver.
They capture the requests made by the existing provider, gateway and chain
checks; test data stays inside the test VMs and their check outputs.

Hydra retains these outputs on test failure using its `nix-support/failed`
convention, so a failing check still has downloadable traces. Local
`nix build .#nixosTests.x86_64-linux.<name>` keeps the usual failing exit status;
use the Hydra attribute when retaining failure outputs is needed. Public
packages still build without telemetry by default.

## Embedding

The CLI and native hosts use `hellas_sdk::paid_gateway::PaidGateway`. Load
the same pool file with `load_pool_options(path, assurance)`,
and pass the resulting typed `PaidGatewayOptions`, a `NodeIdentity`, and an
`Arc<ClientOwner>` to `PaidGateway::open`. Construct the owner with the passkey
authenticator, the identity's settlement key and a private funding directory. Applications can also construct the options directly from
`PaidWorkOptions`; the pool validates duplicate providers and journals before opening connections. It owns recovery, admission, per-channel
serialization and payment tasks. No CLI argument structures are part of its API.

To serve it over HTTP, pass the pool to `hellas_sdk::serve_gateway` with
`GatewayServeOptions`: listener, authentication and archive policy, and the
presentations to add (a text model, HTTPS routes). A Responses route the pool's
providers seal is served too. Shutting down the returned handle drains accepted
paid work. Failed startup also drains
recovery tasks. A host using the pool without a gateway must call its
`WorkExecutionBackend::drain` method when shutting down.

The native SDK includes paid and grant clients, providers, gateways and Apple
verification in one build. Host configuration chooses the services and funding
to assemble; Cargo features do not alter these dispatch paths. Consumers needing
a smaller dependency graph can use the underlying Auth, RPC, Work and client
crates directly. The file loader keeps assertion counters under each provider's existing journal
root in `apple-counters`. CLI paid execution keeps its existing caller-wide counter
directory. Approving or replacing a trust policy never moves or resets those files.
Counter files alone do not trigger channel funding during startup recovery.
Work and WorkSetup each reuse an authenticated QUIC connection. Reconnection
repeats Open with that connection's exporter and the channel's producer pin;
no new consensus query is added to the per-request path.
