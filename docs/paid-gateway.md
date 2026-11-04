# Paid gateway

`hellas --passkey owner.key gateway --paid-work-config /srv/hellas/pool.json
--text-model qwen3.gguf` renders each text request as a Compute job, sends it
to the configured providers and pays through their real funded work channels.
Each provider has its own endpoint identity, bond, payment funding, and client
journals. The gateway skips busy provider channels and serializes requests
within each channel. Providers must already hold the GGUF named by the job (for
example via `hellas store adopt`); the gateway never uploads the weights.

The Qwen3 BF16 program's HIP kernels require a supported gfx11 target, including
the Strix Halo gfx1151 used in the demo. A gfx1010 GPU can run a scalar smoke
test but cannot compile this model's native packed BF16 operations. Check the
model on the target GPU before offering paid inference.

Strix Halo shares system memory with the GPU. An idle worker can retain model
weights, and `--gpu-session-asset-bytes` bounds that cache, not all GPU or process
memory. A systemd memory limit alone does not reserve headroom for another GPU
service. Avoid retaining demo models alongside a GLM deployment that can fill
the machine; stop the completed demo worker to release its GPU allocations.

Whisper uses the same Compute work source. Convert a downloaded multilingual
80-mel Whisper checkpoint once on the client (the checkpoint directory contains
`config.json`, `generation_config.json`, `tokenizer.json`, and `model.safetensors`):

```sh
hellas convert-whisper --checkpoint /models/whisper-tiny-original --output /models/whisper-tiny
```

The resulting `weights.bf16` is the only model asset a provider holds; supply it
through the ordinary content store or `serve --content /models/whisper-tiny/weights.bf16`.
Providers need no renderer, tokenizer, preprocessing code, or preinstalled program.
The converted directory and its metadata stay on the client. An existing gateway
configuration can add `--audio-model /models/whisper-tiny` alongside `--text-model`.
The directory name (`whisper-tiny` here) is its HTTP model name. The same option
works with a paid pool, `--offer` for an owned remote node, or `--local-grant` with
`--content /models/whisper-tiny/weights.bf16` on a supported local GPU.

```sh
curl http://127.0.0.1:8080/v1/audio/transcriptions \
  -H "Authorization: Bearer $GATEWAY_TOKEN" \
  -F model=whisper-tiny -F file=@speech.wav -F language=en -F response_format=json
```

The route accepts mono/stereo WAV up to 30 seconds and 32 MiB, resamples 8–192 kHz
audio to 16 kHz on the client, and returns `{"text":"..."}` or plain text with
`response_format=text`. Language is optional; the program detects it when omitted.
`--default-max-tokens` bounds transcription tokens and must fit the model's decoder.
The audio route has its own body limit, including archival and multipart model
splitting. Ordinary JSON routes retain their existing limit. HTTP format options
and multipart fields are validated before submitting work.
Responses identify the accepted job and provider in `x-hellas-commitment-bin` and
`x-hellas-provider`. JSON includes the signed transcript in its `hellas` object;
plain text carries it in the `x-hellas-transcript` trailer (HTTP/1.1 clients must
send `TE: trailers` to receive trailers). For response formats that trail the
evidence instead of embedding it, a transcript whose base64 encoding exceeds
8 KiB is not delivered to the HTTP caller at all: `x-hellas-transcript` is
omitted and `x-hellas-transcript-digest` names its lowercase hex SHA-256
instead. The digest identifies the canonical signed bytes so a caller who
obtains them out of band can verify them; the gateway does not retain or serve
those bytes, so no HTTP request can retrieve an oversized transcript.

For a single paid job without an HTTP server:

```sh
hellas --passkey owner.key transcribe --provider ENROLLMENT_ID@NODE_ID \
  --model /models/whisper-tiny --audio speech.wav --language en --payment 20
```

This saves the rendered job before submission, uses the existing transaction and
payment journals, and prints decoded text. Both commands ship the same rendered
program and numeric inputs; weight conversion never happens on the provider.

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
limits, maximum steps, the execution limit, `[compute]` with `mode = "any"` and an optional
`[fetch]` section. To restrict Compute to reviewed programs, use
`[compute]` with `mode = "only"` and a nonempty `manifests` list of exact
program manifest content IDs. These bind the rendered code and asset hashes;
request inputs and plans still vary within the configured limits. Omit
`[compute]` to disable Compute. The same explicit `programs` selection applies
to Compute admissions in owner-issued grant policies.

`--faucet` selects only the owner key from the public
devnet faucet allocation; it never sets price or limits. Restarts with the same
file change nothing. A lower stake cap is refused before changing policy if no
already-delegated coin fits it; use the explicit owner `chain delegate --split`
path to reshape unused stake first. The saved `admin.json` profile beside the
provider identity works with the passkey administration commands.

For an existing fleet daemon, keep the owner key on the administration machine.
Approve the same TOML file remotely with its owner profile:

```sh
hellas --identity laptop.identity --passkey owner.key admin \
  --profile node-admin.json --node NODE_ID --address HOST:31145 \
  set-paid-policy --terms paid.toml --expected-revision 0
```

Then start the initialized daemon with `serve --grant-config node.json
--paid-work-config paid.toml`, without a passkey or `--faucet`. It checks the
stored policy matches exactly and cannot approve changed terms itself. Use the
current policy revision for subsequent approvals. A stale revision or a node-key
session cannot change paid terms.

Stake must belong to the authority owner and be delegated to the daemon's
settlement key. From the owner's machine, use `chain delegate --coin COIN_ID
--node SETTLEMENT_KEY --split 12` with `--passkey owner.key`, the independently
pinned `--trust` document and `--rpc` endpoint. Use the stake value configured in
`offers.max_stake_per_client`; the example uses 12. `chain send --coin COIN_ID
--to OWNER_KEY --amount 1000` can fund the owner from a public
`--faucet-account N`. It returns any change to the sender without delegation.
These commands print submission status and resulting coin IDs; submission is
not finalization. Check finalized coin state before relying on the funding.

The first paid daemon startup synchronizes authenticated devnet state before
serving requests. This can take several minutes. Retain its `--chain-store-dir`
across restarts; the CLI reports the wait. A buyer's `--faucet` chooses a public
devnet account and records that choice beside its identity. Use a dedicated
identity and retain its wallet/channel state through settlement.

Paid CLI jobs default to 300 admission blocks, 3000 execution/delivery blocks,
and 600 payment blocks. Override these with `--acceptance-blocks`,
`--terminal-blocks`, and `--payment-blocks`; they count finalized blocks, not
seconds. The gateway pool exposes the same fields and defaults. The provider's
bond lifetime must cover all three windows plus channel setup. `--timeout`
separately limits the caller's wall-clock wait; it does not extend signed deadlines.

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
      "provider": "ENROLLMENT_ID@NODE_ID",
      "provider_addrs": ["192.0.2.10:31145"],
      "payment": 20
    }
  ],
  "acceptance_blocks": 300,
  "terminal_blocks": 3000,
  "payment_blocks": 600,
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
the open channel. `transact --settle --provider ENROLLMENT_ID@NODE_ID` closes it and returns unspent funding.

A request without funding coins returns a quote and writes no paid journal. The
quote states the canonical channel policy, omission collateral and exact funding.
A funded request proves live coins owned by the client's principal and delegated
to its settlement key. Their sum must match the quote exactly. The provider
reserves its own owner-delegated stake within `max_stake_per_client` and
`max_open_offers`, and creates one live offer per client principal and key.
The original signed offer, policy and authenticated peer are durable together;
retries return the same offer and restart requires no route configuration.
Unanswered offers expire at their bond timeout.

`provider` is the address `hellas serve` prints: the content ID of the
provider's enrollment bundle and the node ID it binds. Each live Open checks
that the provider presents exactly that enrollment, that it names the live
transport, and verifies the producer proof; a retained channel whose offer names
another enrollment is refused on restart. Apple-attested providers additionally
require the existing independent trust store.
For those entries, add a top-level `trust_store` directory and a per-provider
`trust_policy` ID. Approve app IDs and release CDHashes independently:

```sh
hellas trust --store /var/lib/hellas-gateway/trust approve provider-a \
  --expected-revision 0 --policy /srv/hellas/provider-a-trust.json \
  --reason 'Reviewed Apple application and release hashes'
```

The existing trust JSON contains `provider_genesis`, `assurance`, and `apple`
with `app_id` and `cd_hashes`; `provider_genesis` must equal the address's
enrollment ID. Missing or mismatched
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
metrics server, gateway/executor instruments and OTLP exporters. The `otel`
build also enables `serve` and `gateway --metrics-port` scraping, with an optional
`--metrics-addr IP` (default loopback, unauthenticated). Transitive dependencies
still include metrics and SDK crates. Nix module `otel` options select enabled builds.

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

The VM checks under `releaseJobs.cli.x86_64-linux.tests` use telemetry-enabled test
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
packages still build without metrics or OTLP export by default.

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

The paid gateway and native paid sessions use the same funding and execution
implementation. A funding cap applies to the actual fresh channel quote, while
a retained channel can be reused without allocating that amount again. A
funding approval reserves the quoted channel amount; each successful job pays
the fixed per-job price. Tracking and recovery behavior is described in
[Tracked native execution](jobs.md#tracked-native-execution).

## Retained settlement and journal upgrades

`hellas transact --settle` and the SDK's `settle_channel` close an existing
funded channel after the entire provider has stopped, including its background
clock. The shared channel driver submits the close start and final adjudicated
transaction, using authenticated finalized blocks from the pinned consensus
chain. It recovers accepted responses, omission penalties, and owner-authority
flags through the same pending-close transitions and payout builder used by the
kernel. This factors existing consensus behavior; it changes no transaction
encoding, consensus rule, or response deadline. Live object-proof RPCs are not
required. Funding is returned to application accounting only after verification
of the finalized close receipt.

For older journals, contest reconstruction covers the accepted start through
the response deadline, or stops sooner after an accepted response. Each verified
block advances durable `CloseHistoryAdvanced` journal progress. Cancellation,
restart, and checkpoint rotation preserve that progress, so repeated bounded
attempts resume at the next unread block even with the maximum legal response
window. Missing or inconsistent evidence remains an error. A source used as
`FinalizedBlocks` must independently authenticate every historical block on the
same pinned consensus chain; an unverified remote RPC connection does not meet
that contract.

The channel journal adds record tag **14** and an optional checkpoint tail for
verified contest history. Existing checkpoints remain readable and require no
separate migration. Once a new binary writes these records or checkpoints,
binaries predating this extension cannot read that journal and fail closed.
A software rollback must therefore retain support for this journal extension;
replacing the binary with an older release is not a compatible rollback. Merely
building or integrating this change does not upgrade running deployments or
rewrite their journals.
