# Paid work on the devnet

A provider sells jobs for devnet coins under terms it publishes; a buyer pays
only for a result signed by that provider that matches its job. Hellas does not
re-run the job, so this shows who answered, not that the answer is correct.

## Sell

Start `hellas serve`, pair its invite, and configure the local packages or
Fetch backends it may execute. Routing uses `backend` and `route` verbs; paid
terms are a separate owner-approved policy in the same authority.

```sh
hellas faucet
hellas serve
# In another shell, pair the printed invite, then configure a package:
hellas pair hellas-invite:… --name mine
hellas route add /srv/models/whisper-tiny
hellas admin work docs/examples/faucet-provider.json
```

Run the example from the repository root with the paired owner's passkey
(`--passkey PATH`, or the owner's configured key). With several paired nodes,
select this node using `hellas admin --profile "$HOME/.hellas/nodes/mine/profile.json"
work docs/examples/faucet-provider.json`.

The JSON is a complete `WorkControlCommand`: `SetPaidPolicy` contains
`expected_revision` and `policy`. The first approval expects revision 0 and
returns `{"PaidPolicyChanged":{"revision":1}}`. For later approvals, copy the
file and set `expected_revision` to the last returned revision. Stale revisions
and daily node-key sessions cannot change paid terms.

The policy's `invocation_policy` names the evaluator shown by `hellas routes`.
Change the example's HIP evaluator if the provider uses another runtime. Its
`programs: {"mode":"any"}` allows arbitrary programs for that evaluator;
restrict it to `{"mode":"only","manifests":["CONTENT_ID"]}` to allow only
specific program manifests. Those programs run with the provider process's
filesystem and device access. The example sells Compute only; Fetch requires
an explicit Fetch admission in the same policy.

`payment_policy` sets price and block margins; `channel_policy` limits credit;
`offers` bounds automatic funding. At price 20 and 10 jobs per channel, capacity
is 200. The example adds omission collateral 201 and uses zero close fees, so
`expected_payment_values.value` is 401 and `reserve` is 0. Keep these amounts
consistent when changing the price or channel size. Existing channels retain
their signed terms.

Stake must belong to the authority owner and be delegated to the daemon's
settlement key. Use `chain delegate --coin COIN_ID --node SETTLEMENT_KEY
--split AMOUNT` with the owner's key and independently pinned chain. Check
finalized coin state before relying on funding. Retain the daemon's home and
all channel journals across restarts.

The provider address combines its enrollment ID and transport node ID. Buyers
pin that enrollment; native programs run with the provider user's permissions.
Only admit programs you trust. A policy admitting arbitrary programs grants
those callers the same filesystem and device access as the provider process.

## Buy

```sh
hellas faucet
hellas transcribe --model whisper-tiny --audio speech.wav --pay 20 --provider ENROLLMENT_ID@NODE_ID \
  --backend hellas/catena-f47ade17aa5f-hip
hellas transact --settle --provider ENROLLMENT_ID@NODE_ID
```

The client renders the program for `--backend`, the renderer the provider's GPU
runtime registers, before anything else; a provider refuses a program for an
evaluator it did not register. `--pay MAX` asks the provider for a quote first, refuses it above `MAX`, and only
then builds and signs the job at exactly the quoted price. `transcribe`,
`text`, `image`, `run`, `fetch` and `gateway` take the same flags; a saved
`transact --job DIR` keeps its own signed price. The first job opens a channel
and later jobs reuse it; `transact --settle` closes it and returns the unspent
part. This saves the rendered job before submission, uses the existing
transaction and payment journals, and prints decoded text.

Paid CLI jobs default to 300 admission blocks, 3000 execution/delivery blocks,
and 600 payment blocks. Override these with `--acceptance-blocks`,
`--terminal-blocks`, and `--payment-blocks`; they count finalized blocks, not
seconds. The provider's
bond lifetime must cover all three windows plus channel setup. `--timeout`
separately limits the caller's wall-clock wait; it does not extend signed deadlines.

Execution limits are A's: a job over the upload limit is refused before it
runs, and a job that exceeds `execution_timeout_ms` is killed with its worker
process group and is not paid. Catena jobs run in a separate worker process;
that isolation is crash/timeout containment, not a sandbox, and there is no
memory metering. Before paying, the client checks that each result is signed
by the provider and matches this job; Hellas does not re-run it.

Compute terms should allow at least 4 MiB of upload for Whisper. The faucet
example uses `"max_upload_bytes": 4194304`; provider and grant limits are explicit
terms, with no implicit runtime default. Whisper ships roughly 0.47–0.85 MB of
rendered program, 960,000 bytes of log-mel features, and three F32 vocabulary
masks (622,380 bytes for a 51,865-token model). The allowance also covers input
metadata. The client includes the program with every job; a provider may deduplicate
received sources by content ID, but never needs a preinstalled model program.
Weights remain a separate ordinary content-addressed asset.

The process selects one chain with `--chain devnet` or `--chain-config FILE`.
The custom JSON file contains the exact `genesis_json` bytes as a JSON string,
`trust`, and a nonempty `validators` URL list. The buyer and gateway start
no chain node. They authenticate remote state against the selected genesis and
trust; relay URLs supply transport only.
`transact` defaults to the embedded devnet trust and
`wss://devnet.hellas.ai/ws/validator-{0..5}`. Local transport and settlement
keys are created on first use and retained with the identity.

The buyer's principal key funds channels; on the devnet, `hellas faucet` gives it
coins. A new channel asks for one owner approval over its exact quoted amount: the
provider's jobs per channel times its price, plus omission reserve and fees.
At most four eligible owner coins fund one delegated output; change returns
undelegated to the same owner. The wallet records the signed reshape before
submission and shares reservations across jobs and gateways. Later jobs reuse
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

`--provider` takes the address `hellas serve` prints: the content ID of the
provider's enrollment bundle and the node ID it binds. Each live Open checks
that the provider presents exactly that enrollment, that it names the live
transport, and verifies the producer proof; a retained channel whose offer names
another enrollment is refused on restart. Apple-attested providers additionally
require the existing independent trust store: pass `--trust-store DIR` and
`--trust-policy ID`. Approve app IDs and release CDHashes independently:

```sh
hellas trust --store /var/lib/hellas-gateway/trust approve provider-a \
  --expected-revision 0 --policy /srv/hellas/provider-a-trust.json \
  --reason 'Reviewed Apple application and release hashes'
```

The existing trust JSON contains `provider_genesis`, `assurance`, and `apple`
with `app_id` and `cd_hashes`; `provider_genesis` must equal the address's
enrollment ID. Missing or mismatched
Apple approval fails before funding or disclosure. Approval replacement retains
its revision checks and persistent assertion counters. Software providers do not
need them. Granted jobs and gateways keep the same independent approval requirements.

Owners delegate or reclaim coins with their principal key:

```sh
hellas --chain-config ./chain.json chain delegate --rpc ws://127.0.0.1:8788 \
  --node NODE_SETTLEMENT_KEY \
  --coin COIN_ID --split 12
hellas --chain-config ./chain.json chain sweep --rpc ws://127.0.0.1:8788 \
  --coin COIN_ID
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
The provider verifies the buyer's delegated funding and retains the
first authenticated peer with its offer. All participants must use the same
compatible chain revision.

## Paid HTTP backends

Embedding applications can put a `Paid` backend and model/HTTP routes in a
`daemon_config::Document`, then run `daemon::Core`. Each backend names its
provider, maximum price, evaluator and optional approved trust policy. Several
requests share its channel within the configured capacity; proposals serialize
only the channel negotiation, and collection and settlement remain owned by
each job. The stateless CLI exposes local models, grants and upstreams.

HTTP Fetch routes use the same paid channels. The provider's paid policy must select the HTTP Fetch manifest and a
matching Fetch route policy; see [HTTP routing](http-gateway.md).

Each text job fixes the rendered program, the GGUF weights, the prompt tokens
and the token budget (`max_tokens`, else the presentation default), cut to what
the quoted or granted terms allow. The provider's step loop feeds each emitted
token back until that budget; a spent budget ends the response with the API's
length stop. The payment terms fix the price per job. Model presentation (the
GGUF's embedded Jinja chat template and Qwen3/Qwen3.5 function tools)
lives in the shared `hellas-presentation` adapter, usable by clients and the
gateway.

The provider reserves delivery credit before streaming signed output prefixes.
The gateway verifies each prefix as it arrives, then authenticates and journals
the complete result and obtains the provider's durable payment acknowledgement
before reporting completion. One open subscription replaces repeated result
polls. Payment is an accumulating channel certificate. An established, healthy
channel performs no validator RPCs on its request or streaming paths. Requests
use local credit checks, signatures and journal commits. Channels settle through
the existing close protocol; nothing refills them automatically.

Each channel observes finalized history independently of its requests. The client
has one request owner and a separate observer handle, so a slow response cannot
block close monitoring or reorder payment exchanges. The provider also drives
channels independently: one stalled channel cannot block another's recovery.
Applying a close and crediting a certificate use the same short journal lock.
Jobs within a channel still finish in order, including collection and payment
after an HTTP client disconnects. A server that keeps an HTTP response open after
an application completion event therefore holds that channel until EOF. The
generic HTTP route preserves those trailing bytes. Separate funded channels
execute independently.

Both endpoints follow a channel by proof-checked reads of its current state:
the payment edge, the bond and its lease, and the pending-close slot, at one
certified block. Each read moves the channel journal's cursor to that block;
nothing between reads is replayed. Admission, delivery and new certificates
stop when the latest read is older than the certified-age bound, measured from
the block's own timestamp. Results may still be retained during an observation
outage; existing payment certificates remain safe to retransmit.

This is an online channel: its observer must detect unilateral closes and
answer them before the response deadline, which is the inclusion block's time
plus `RESPONSE_WINDOW_MS` (two minutes). The provider reads every channel at an
interval derived from that window, and faster while a contest is live or a
transaction it sent is waiting to land. The certified-age bound is derived from
the same window, so a reachable watcher answers in time; an observer cut off
from every validator for longer than the window can lose an answer.

Keep gateway and provider identities and journals across service restarts,
including when the operating system's store is ephemeral. Startup recovers
retained Compute jobs and re-sends payment certificates idempotently. Fetch
journals omit bodies. A verified delivery recorded before a crash is paid from
its retained evidence, even when the payload is gone. Jobs without either payload
or verified delivery retain their credit reservation until the payment deadline;
recovery skips them and never submits them anew. Disconnecting an
HTTP client cancels work that has not yet been proposed. Once a signed proposal
may have reached a provider, collection and payment continue despite disconnects.
Each backend bounds its queued and running requests with `max_in_flight`.
A full backend refuses new work; other eligible backends can take an unproposed request. SIGTERM and wrapped-command failures drain
outstanding operations. An operation that reaches its deadline retains its
journal for recovery, as does abrupt process termination.

All HTTP requests require a scoped gateway bearer. See [HTTP authority](admin.md#http-gateway-authority)
and the [HTTP gateway guide](http-gateway.md) for stateless and persistent services.

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

Useful spans include `http.server`, `paid.gateway`, GenAI `chat MODEL` and `text_completion` operations,
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

The CLI and Gate use `hellas_sdk::daemon::Core` with one complete document.
Backends are `Local`, `Fetch`, `Grant` or `Paid`; routes select ordered backend
IDs. `Configure` prepares and commits a replacement document atomically.
`Watch` reports the document, health and in-flight jobs; `CancelJob` retains
accepted remote settlement duties. Call `Core::shutdown` before closing the
host's content and authority stores. Wrapped children belong to the CLI.

Tracking and recovery behavior is described in
[Tracked native execution](jobs.md#tracked-native-execution).

## Retained settlement and journal upgrades

`hellas transact --settle` and the SDK's `settle_channel` close an existing
funded channel after the entire provider has stopped, including its background
clock. The shared channel driver submits the close start as soon as it is
signed, and the final adjudicated transaction once the read shows the contest
answered or its deadline passed, built from the pending-close record that
read carries. A source that fails is replaced by the next configured
validator. Funding is returned to application accounting only after a read
shows the payment edge consumed; the receipt's amounts are the two payout
coins the close issues at fixed ids.
