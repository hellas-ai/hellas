# Paid gateway

`hellas-cli --passkey owner.key gateway --paid-work-config /srv/hellas/pool.json` sends token-native
inference to the configured providers and pays through their real funded work
channels. Each provider has its own endpoint identity, bond, payment funding,
and client journals. The gateway prefers idle matching providers and matching
prompt prefixes, then serializes requests within each channel.

With `--http-fetch-config`, the same pool carries HTTP Fetch requests. Its paid
policy must select the HTTP Fetch manifest and a matching Fetch route policy;
see [HTTP routing](http-gateway.md). The HTTP router chooses the provider and
account, so this path never falls back to a different provider or funding source.

The provider keeps its paid policy in its node authority. A passkey-authenticated
owner sets it with `hellas-cli admin work policy-command.json`, using a
`SetPaidPolicy` command with `expected_revision` and `policy`. The policy contains
its channel credit, execution and payment policies, expected payment-edge values,
response window, `jobs_per_channel` (default 10), and offer bounds. A stale revision
or a daily node-key session cannot change it.

For public devnet onboarding, `hellas-cli serve --faucet` selects and retains one
published faucet owner with the provider identity. It uses the embedded public devnet genesis
and offline seed-100 trust export; the six relay URLs are transports and supply no
trust pins. `--work-config` and `--chain-store-dir` still override chain deployment
and storage. `--faucet-account N` selects a specific account on its first start.
An existing provider cannot change its saved account with this flag.

Faucet startup bootstraps the normal authority, approves a real HTTP Fetch policy
through an owner passkey session, and delegates up to three 12-credit coins with
undelegated change. It records the exact signed owner transaction before submission
and confirms its inclusion in finalized history. Restarts retain the original
policy revision/salt and delegation, including when a bond has consumed its output.
It never takes coins already delegated to another provider sharing that public owner.

Initial defaults are price 20, ten jobs/channel, stake cap 12/client, three open
offers, a 256-block bond lifetime, 1 MiB signed upload, 64 KiB request body,
1 MiB output, 1024 output events and 4 MiB spool. The paid Fetch executor stops
execution after 90 seconds; grant execution keeps its own signed deadline. HTTP
uses the built-in contract, public-address egress and a caller-supplied SPKI pin.
No upstream API credential is installed.

Override onboarding with `--paid-price`, `--paid-jobs-per-channel`,
`--paid-max-stake-per-client`, `--paid-max-open-offers`,
`--paid-bond-lifetime-blocks`, `--paid-max-upload-bytes` and
`--paid-execution-timeout-secs`. Price/jobs changes derive exact payment funding
and omission collateral together. Explicit policy changes are owner-approved;
plain restarts preserve existing policies and the saved execution timeout. A lower
stake cap is refused before changing policy if no already-delegated coin fits it;
use the explicit owner `chain delegate --split` path to reshape unused stake first.
The initial delegation is a fixed owner budget and is never topped up on restart.
The saved `<identity>.faucet/admin.json` profile works with the existing passkey
administration commands. Without a faucet flag, owner approval and delegation
remain explicit.

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
URLs supply transport only. `paid-work run` defaults to the embedded devnet trust
and `wss://devnet.hellas.ai/ws/validator-{0..5}`. Local transport and settlement
keys are created on first use and retained with the identity.

Use `--passkey owner.key`, `--faucet`, or `--faucet-account N` for channel funding.
A new channel asks for one owner approval over its exact quoted amount: the
provider's jobs per channel times its price, plus omission reserve and fees.
At most four eligible owner coins fund one delegated output; change returns
undelegated to the same owner. The wallet records the signed reshape before
submission and shares reservations across gateway providers. Later jobs reuse
the open channel. `paid-work run --settle` closes it and returns unspent funding.

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
hellas-cli trust --store /var/lib/hellas-gateway/trust approve provider-a \
  --expected-revision 0 --policy /srv/hellas/provider-a-trust.json \
  --reason 'Reviewed Apple application and release hashes'
```

The existing trust JSON contains `provider_genesis`, `assurance`, approved
`environments`, and `apple` with `app_id` and `cd_hashes`. Missing or mismatched
Apple approval fails before funding or disclosure. Approval replacement retains
its revision checks and persistent assertion counters. `paid-work run` accepts
`--trust-store` and `--trust-policy` for Apple providers; software providers do not
need them. Grant gateways keep their existing independent approval requirements.

Owners delegate or reclaim coins through the global passkey:

```sh
hellas-cli --passkey owner.key chain delegate --rpc ws://127.0.0.1:8788 \
  --trust ./chain-trust.json --network devnet --node NODE_SETTLEMENT_KEY \
  --coin COIN_ID --split 12
hellas-cli --passkey owner.key chain sweep --rpc ws://127.0.0.1:8788 \
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

Pass the environment, tokenizer, model label, `--default-max-tokens`, and
`--stop-token` options as for an ordinary gateway. The work policy fixes
the environment, maximum output tokens and stop IDs; separate payment terms
fix the price per job. Requests
may request a shorter output within the configured ceiling. Model presentation
lives in the shared `hellas-presentation` adapter, usable by clients and the
gateway. Select `--chat-template qwen3` for chat messages and function tools;
the adapter binds the input template and output parser to the same offered tools.
Catena execution receives committed tokens and generation settings.

The provider reserves delivery credit before streaming signed token prefixes.
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

The shared `--output-cache record` mode also covers paid inference. Repeating
an identical recorded request reuses its output without another paid job. A
recording becomes replayable only after successful completion and payment
acknowledgement; `--output-cache replay-only` reads it without connecting to
providers or validators.

Keep gateway and provider identities and journals across service restarts,
including when the operating system's store is ephemeral. Startup recovers
retained Evaluate jobs and re-sends payment certificates idempotently. Fetch
journals omit bodies. A verified delivery recorded before a crash is paid from
its retained evidence, even when the payload is gone. Jobs without either payload
or verified delivery retain their credit reservation until the payment deadline;
recovery skips them and never submits them anew. Disconnecting an
HTTP client cancels work that has not yet been proposed. Once a signed proposal
may have reached a provider, collection and payment continue despite disconnects.
The pool admits at most `max_pending_requests` queued or running requests (default
64); additional requests receive HTTP 503 and may be retried. `timeout_secs`
bounds queueing, recovery, provider fallback, execution and payment together,
rather than restarting for each provider. Token-native requests skip busy provider
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
`authorityJournal` when the authority journal is outside the managed state directory,
alongside the existing environment and tokenizer options.


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
attributes. GPU spans report queue wait, first-token latency, cache reuse and
input/output token counts; HTTP spans report first body delivery, status, byte
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

## Prefill and prefix reuse

Every environment commits a fixed generation capacity and prefill chunk size.
The Qwen example uses capacity 32768 and chunks of 64 tokens to bound temporary
allocations at long contexts. Build the environment from settings containing
`[generation]`, `fixed_capacity`, and `prefill_chunk_tokens`; the resulting
manifest identity binds that schedule as well as the program and weights.

The provider must admit the fixed capacity even for short requests. Catena
retains at most one prefix checkpoint per GPU worker, capped at 8 GiB and
charged to the generation's device-memory envelope. The cap bounds that single
checkpoint, not a collection of conversations. Reuse requires an exact token
prefix and the same model, capacity and chunk size. State buffers are copied
independently, so generation cannot mutate the retained checkpoint.

Catena may preserve a compatible checkpoint across requests of at most two
prefill chunks when its memory budget permits. The gateway conservatively
clears its affinity hint after short requests; the provider decides actual
reuse. Worker spans report that observed reuse as
`gen_ai.usage.cache_read.input_tokens` without recording token values.

## Embedding

The CLI and native hosts use `hellas_sdk::paid_gateway::PaidGateway`. Load
the same pool file with `load_pool_options(path, assurance)`,
and pass the resulting typed `PaidGatewayOptions`, a `NodeIdentity`, and an
`Arc<ClientOwner>` to `PaidGateway::open`. Construct the owner with the passkey
authenticator, the identity's settlement key and a private funding directory. Applications can also construct the options directly from
`PaidWorkOptions`; the pool validates duplicate providers and journals before opening connections. It owns recovery, admission, per-channel
serialization and payment tasks. No CLI argument structures are part of its API.

For transparent HTTP, pass this pool to `hellas_gateway::start_http` using
`HttpGatewayOptions`. Its `paid` field is required. The options contain HTTP
routes, archive policy, listener authentication and optional process wrapping;
they have no model, tokenizer, inference cache or Evaluate settings. Shutting
down the returned handle drains accepted paid work. Failed startup also drains
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
