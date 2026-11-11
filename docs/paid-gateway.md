# Paid work on the devnet

A provider sells jobs for devnet coins under terms it publishes; a buyer pays
only for a result signed by that provider that matches its job. Hellas does not
re-run the job, so this shows who answered, not that the answer is correct.

## Sell

Fund the home's principal, then serve paid terms:

```sh
hellas faucet
hellas serve --knowingly-unsafe --paid-work-config docs/examples/faucet-provider.toml --content whisper-tiny
```

`serve` prints the provider address, `Provider: ENROLLMENT_ID@NODE_ID`: the
content ID of the provider's enrollment and the node it binds. Buyers learn it
out of band, and every paid connection must present exactly that enrollment.
The example charges 20 per job, ten jobs per channel, and stops execution after
90 seconds. `--content PATH` serves the converted weights the jobs name; the
provider never converts or renders anything.

The provider keeps its paid policy in its node authority. A provider started
with `serve --paid-work-config FILE` has its principal (the home's
`principal.key`, or `--passkey`) approve exactly that file's terms at startup,
unless the authority already holds them, and delegate the stake its offers
bond. Paid work is sold only with this file; nothing has a built-in
default. [`faucet-provider.toml`](examples/faucet-provider.toml) is a complete
example: price, jobs per channel, channel credit, offer bounds, upload/output
limits, maximum steps, the execution limit, `[compute]` with `any` set to a compute
id (the evaluator a GPU runtime registers, such as `hellas/catena-dfad87438018-hip`)
and an optional `[fetch]` section. `any` admits any program of that compute id,
which hands anyone who can submit jobs roughly root on the host, so `serve`
refuses it unless `--knowingly-unsafe` acknowledges that. To restrict Compute to
reviewed programs, use `[compute]` with a nonempty `only` list of program ids;
`hellas program PATH` prints the id of a converted Whisper package or a Qwen GGUF. These bind the rendered code and asset hashes;
request inputs and plans still vary within the configured limits. Omit
`[compute]` to disable Compute. The same explicit `programs` selection applies
to Compute admissions in owner-issued grant policies.

Restarts with the same
file change nothing. A lower stake cap is refused before changing policy if no
already-delegated coin fits it; use the explicit owner `chain delegate --split`
path to reshape unused stake first. The saved `admin.json` profile beside the
provider identity works with the passkey administration commands.

For an existing fleet daemon, keep the owner key on the administration machine.
Approve the same TOML file remotely with its owner profile:

```sh
hellas admin --profile node-admin.json --node NODE_ID --address HOST:31145 \
  set-paid-policy --terms paid.toml --expected-revision 0
```

Then start the initialized daemon with `serve --grant-config node.json
--paid-work-config paid.toml`, without a principal key. It checks the
stored policy matches exactly and cannot approve changed terms itself. Use the
current policy revision for subsequent approvals. A stale revision or a node-key
session cannot change paid terms.

Stake must belong to the authority owner and be delegated to the daemon's
settlement key. From the owner's machine, use `chain delegate --coin COIN_ID
--node SETTLEMENT_KEY --split 12` with the owner's principal key, the independently
pinned `--chain` or `--chain-config` selection and `--rpc` endpoint. Use the stake value configured in
`offers.max_stake_per_client`; the example uses 12. `hellas faucet` funds the
owner on the devnet. These commands print submission status and resulting coin IDs; submission is
not finalization. Check finalized coin state before relying on the funding.

The first paid daemon startup synchronizes authenticated devnet state before
serving requests. This can take several minutes. Retain its `--home` directory across restarts; the CLI reports the wait. Chain state is stored under `<home>/chains/<full consensus digest>/`. Buyers
likewise retain their home's wallet and channel state through settlement.

The Qwen3 BF16 program's HIP kernels require a supported gfx11 target, including
the Strix Halo gfx1151 used in the demo. A gfx1010 GPU can run a scalar smoke
test but cannot compile this model's native packed BF16 operations. Check the
model on the target GPU before offering paid inference.

Strix Halo shares system memory with the GPU. An idle worker can retain model
weights, and `--gpu-session-asset-bytes` bounds that cache, not all GPU or process
memory. A systemd memory limit alone does not reserve headroom for another GPU
service. Avoid retaining demo models alongside a GLM deployment that can fill
the machine; stop the completed demo worker to release its GPU allocations.

## Buy

```sh
hellas faucet
hellas transcribe --model whisper-tiny --audio speech.wav --pay 20 --provider ENROLLMENT_ID@NODE_ID
hellas transact --settle --provider ENROLLMENT_ID@NODE_ID
```

`--pay MAX` asks the provider for a quote first, refuses it above `MAX`, and only
then builds and signs the job at exactly the quoted price. `transcribe`,
`text`, `image`, `run`, `fetch` and `gateway` take the same flags; a saved
`transact --job DIR` keeps its own signed price. The first job opens a channel
and later jobs reuse it; `transact --settle` closes it and returns the unspent
part. This saves the rendered job before submission, uses the existing
transaction and payment journals, and prints decoded text.

Paid CLI jobs default to 300 admission blocks, 3000 execution/delivery blocks,
and 600 payment blocks. Override these with `--acceptance-blocks`,
`--terminal-blocks`, and `--payment-blocks`; they count finalized blocks, not
seconds. `gateway --pay` takes the same flags and defaults. The provider's
bond lifetime must cover all three windows plus channel setup. `--timeout`
separately limits the caller's wall-clock wait; it does not extend signed deadlines.

Execution limits are A's: a job over the upload limit is refused before it
runs, and a job that exceeds `execution_timeout_ms` is killed with its worker
process group and is not paid. Catena jobs run in a separate worker process;
that isolation is crash/timeout containment, not a sandbox, and there is no
memory metering. Before paying, the client checks that each result is signed
by the provider and matches this job; Hellas does not re-run it.

Compute terms should allow at least 4 MiB of upload for Whisper. The faucet
example uses `max_upload_bytes = 4194304`; provider and grant limits are explicit
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

## Paid gateway

`hellas gateway --model qwen3.gguf --pay 20 --provider ENROLLMENT_ID@NODE_ID`
asks the provider for its quote once, then renders each request as one job and
pays for it on the provider's channel, one request at a time. A converted
Whisper package as `--model` serves `/v1/audio/transcriptions`:

```sh
hellas gateway --model whisper-tiny --pay 20 --provider ENROLLMENT_ID@NODE_ID &
curl http://127.0.0.1:8080/v1/audio/transcriptions \
  -H "Authorization: Bearer $(cat ~/.hellas/gateway/bearer)" \
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

With `--http-fetch-config`, the gateway carries HTTP Fetch requests on the same
channel. The provider's paid policy must select the HTTP Fetch manifest and a
matching Fetch route policy; see [HTTP routing](http-gateway.md).

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
A gateway admits at most 32 queued or running requests; further requests are
refused and may be retried. SIGTERM and wrapped-command failures drain
outstanding operations. An operation that reaches its deadline retains its
journal for recovery, as does abrupt process termination.

A loopback gateway keeps its own authority and bearer under its home. A
non-loopback listener requires `--allow-remote` and an explicitly provisioned
`--gateway-profile` ([HTTP authority and scoped credential](admin.md#http-gateway-authority));
use a trusted network or a TLS reverse proxy. The NixOS options are
`services.hellas.gateway.pay` with `provider`, `models`, `home` (containing
client journals), and `gatewayProfile` with `allowRemote`.

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

The CLI runs every gateway request through `hellas_sdk::ExecutorGateway`: one
`GatewayTarget` (`Paid`, `Grant` or `Local`), each request one job through the
same `Executor` as the job commands. `ExecutorGateway::new(target, signer)`
takes a paid target's quoted policy, endpoint, settlement key and
`Arc<ClientOwner>`; construct the owner with the principal authenticator, the
identity's settlement key and a private funding directory. To serve it over
HTTP, pass it to `hellas_sdk::serve_gateway` with `GatewayServeOptions`:
listener, authentication and archive policy, and the presentations to add
(models, HTTPS routes). A Responses route the provider seals is served too.
Shutting down the returned handle drains accepted work. A host using the
gateway without HTTP must call its `WorkExecutionBackend::drain` method when
shutting down.

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
