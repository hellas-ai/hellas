# Hellas

Hellas commits exact work, runs it locally or over an adversarial network, and
binds the result into a signed transcript. Execution identity is one canonical
`ProgramManifest`:

```text
(evaluator, adaptor, content-addressed application root)
```

The two application identifiers are exact opaque strings. Hellas does not
parse versions, negotiate compatibility, or consult a model/package registry.

## Execution boundary

The application owns the meaning of its root. The two applications
intentionally have different trust boundaries:

| Application | Root and trusted computation | Outside that guarantee |
| --- | --- | --- |
| `hellas/catena-d116170a7e66`, `compute-0.0.1` | Exact Catena Hex sources, named content-addressed assets, inputs, the call plan (calls, optional step loop and stop rule) and declared outputs | Where sources and weights come from, provider GPU/backend choice, tokenizer, chat template, text decoding, and API presentation |
| `hellas/fetch-0.0.2`, the contract's adaptor (`http-0.0.1`, `codex-responses-0.0.2` or `openai-responses-0.0.3`) | A strict stateless Responses field set; typed reconstruction of provider-shaped JSON; `stream=true` and upstream `store=false`; the exact official Codex or OpenAI HTTPS endpoint; no redirects; and SSE response projection | The truth, correctness, and availability of the adversarial upstream service; provider route label; credentials/auth-file location; and access policy |

Fetch's purpose is to attest the exact transformation around a
remote request, so structuring and destructuring are inside that application's
trusted path rather than presentation performed outside it. This proves which
checks and transformation ran, not that the remote service's claims are true.

A platform-backed Assurance authenticates the Fetch application. The
`ProducerSigned` mode authenticates only the producer key and signed transcript;
it does not authenticate a running binary. The sealed Responses adaptor sends
`store=false` upstream and accepts text and client-executed function tools.

Work is the execution protocol for payment-funded channels and owner, principal
and delegated grants, including `gateway --offer` and sealed Fetch. Accepted
paid inputs and results remain in the channel's recovery/evidence journal,
independently of gateway archive settings.

## Quickstart: sell and buy one job

Person A sells GPU compute on the devnet with a GPU build (`.#cli` or
the `hip`/`cuda` image below):

```sh
hellas --faucet serve --paid-work-config docs/examples/faucet-provider.toml
```

`--faucet` only selects a key from the devnet genesis faucet allocation. These
are public development keys; the selected account is retained beside the
identity, and `--faucet-account N` picks one. It sets no price or limits. Paid
work is sold only with `--paid-work-config FILE`: at startup the selected owner
approves exactly that file's terms and delegates the stake its offers bond.
The example charges 20 per job, ten jobs per channel, and stops execution after
90 seconds. `serve` prints A's provider address, `ENROLLMENT_ID@NODE_ID`: the
content ID of A's enrollment and the node it binds. B learns it from A out of
band and every paid connection must present exactly that enrollment.

Person B runs no node. With a Catena program `counter.hex`:

```text
(def program initialize : [] -> (u64 val) = const.u64.0x0000000000000000)
(def program advance : {(u64 val) (u64 val)} -> (u64 val)
= ({smolcat.value.named smolcat.value.named stdlib.numeric.numeric.u64} stdlib.numeric.+ :.forget))
```

one command builds a job, pays A and prints the result; a second closes the
channel:

```sh
hellas --faucet run --provider ENROLLMENT_ID@NODE_ID --source counter.hex --entry advance \
  --arg u64:2 --arg u64:3 --returns u64 --payment 20
hellas --faucet transact --settle --provider ENROLLMENT_ID@NODE_ID
```

B's key approves funding once per channel: A's jobs per channel times its
price, plus reserve and fees. Later jobs reuse the open channel; `--settle`
closes it and returns the unspent part. Before paying, B checks that the result
is signed by A and matches this job. Hellas does not re-run the job, so this
shows who answered, not that the answer is correct.

`run` writes a job folder and transacts it exactly as `hellas transact
--job DIR`, the raw command for any application. `hellas fetch URL` does
the same for a paid HTTPS request. See [jobs](docs/jobs.md) for the folder
format, multi-step jobs and Fetch.

A compiles the Catena sources for its visible GPU and runs each job in a
separate worker process group. That isolation is crash/timeout containment,
not a sandbox: it does not confine what the program can reach, and there is no
memory metering. A job over A's upload limit is refused before it runs; a job
that exceeds the execution limit is killed with its worker and is not paid.
Compilation has no time limit. Sources and weights a job names by content ID
must be available to A: index local files with `serve --content FILE` or
`--content-root DIR`, or adopt a HuggingFace cache with `hellas store adopt`.
Both commands default to the same store (`HELLAS_STORE_DIR` or
`~/.hellas/store`).

Indexed provider content is an immutable local-cache assumption. Hellas pins
the verified read-only descriptor and detects path/inode replacement; it does
not defend against a separate local process that already holds a writable
descriptor to the same inode and mutates it concurrently.

## Sealed Fetch

Fetch route names are operator-defined routing labels. The sealed destination
selects the trusted adaptor, fixed official endpoint, no-redirect HTTP driver,
and response projector as one unit. A configuration cannot supply a URL or
claim a different adaptor identity.

A provider route file contains a `routes` array. Each route has `service`,
`method`, `destination` and optional `capabilities` (model and output limits).
The former `callers` field is rejected; the mounted Work channel authorizes jobs.
Use `serve --fetch-config FILE --paid-work-config FILE` to sell it.
See [paid Work](crates/channel/README.md) for channel configuration and
[HTTPS Fetch](crates/providers/HTTPS.md) for provider credentials and egress.

## HTTP gateway

For upstream APIs, [HTTP Fetch routes](docs/http-gateway.md) preserve the vendor's
request, response and streaming formats. CLI gateways archive payloads by default;
`--zdr` or `x-hellas-zdr: true` disables application payload persistence.

`--text-model` also runs without a chain: `--local-grant ID` serves this
node's own configured allowance in process (with the `serve` content and GPU
flags), and `--offer ALIAS` reaches an allowance on another node you own. Such
memory-only jobs read weights the provider already holds; they never write them.

`--text-model FILE.gguf` serves a dense Qwen3 GGUF on the text routes. The
gateway renders each request as a Compute job from the GGUF's configuration
and tokenizer and sends it to its paid pool or grant; the weights are not
uploaded, so providers must already hold that GGUF (see the quickstart). The
API model label is the file name without its extension.

Buy a single job with [`run`, `transact` or `fetch`](docs/jobs.md).
Configure a funded pool using the [paid gateway guide](docs/paid-gateway.md),
then pass `--paid-work-config POOL` together with `--text-model`.

It binds loopback by default; non-loopback listening requires `--allow-remote`.
Every gateway requires a private `--gateway-profile FILE` selecting a provisioned
local Auth authority and a bearer credential scoped to `gateway.invoke`.
See [HTTP authority provisioning](docs/admin.md#http-gateway-authority). The
text routes use the shared Qwen3 model adapter for completions, chat and tool
calls. One gateway serves every presentation its work source admits: the text
routes with `--text-model`, `/v1/responses` as a Fetch when the source seals
one Responses route, and exact HTTPS routes from `--http-fetch-config` or a
grant's HTTPS resource. A path served by several presentations is split by the
request's `model`; overlapping models refuse to start. See the
[HTTP gateway guide](docs/http-gateway.md#responses-grants).

The exposed routes are:

```text
POST /v1/completions
POST /v1/responses
POST /v1/chat/completions
POST /v1/messages
```

Monitor discovery and peer health with `hellas monitor --timeout-secs 30`.

## Chain

The standard CLI includes `chain query`, `chain open`, and `chain close`.
The `indexer` feature adds `chain indexer follow`; the `validator` feature adds
`chain validator config`, `chain validator run`, and
`chain validator check-config`.

Validator metrics default to `127.0.0.1`. A remote scraper requires an explicit
`metrics_bind_address` in validator TOML, `--metrics-bind-address` when generating
it, or `services.hellas-chain-validators.<name>.metricsBindAddress` in NixOS.
For the devnet's VictoriaMetrics WireGuard scrape, set that option to each
validator host's WireGuard IP before deploying this change.

`chain query --rpc URL` supports `latest-block`, `state-root`, `finalization`,
`finalized-block`, `coin`, `edge`, `validators`, `coins-by-owner`, and
`edges-by-owner`.

`chain open` reads each 32-byte secret scalar from `--maker-key FILE` and
`--taker-key FILE`; `--maker-auth` and `--taker-auth` accept `webauthn` or
`native`. Funding IDs use repeatable or comma-separated `--maker-funding` and
`--taker-funding`. Terms use `--protocol`, `--timeout`, and repeatable or
comma-separated `--timeout-payout SETTLEMENT_KEY:VALUE`. `--terms-out FILE`
writes the canonical reveal for a later timeout close.

`chain close --kind mutual` takes repeatable or comma-separated
`--payout SETTLEMENT_KEY:VALUE` plus both key and auth pairs. `--kind timeout`
takes the same committed payouts and `--terms-file FILE`, with no signer
options.

Stored ownership uses raw, untagged 33-byte settlement keys. P-256 and
secp256k1 keys can own stored coins. The single kernel `Auth` verifier selects
the curve from the authorization variant.

Given two P-256 key files whose settlement keys each own a 100-value coin:

```bash
RPC=ws://127.0.0.1:56946
MAKER_KEY=maker.key
TAKER_KEY=taker.key
MAKER_OWNER=maker-settlement-key
TAKER_OWNER=taker-settlement-key
MAKER_COIN=maker-coin-id
TAKER_COIN=taker-coin-id

OPEN=$(
  cargo run -- chain open \
    --rpc "$RPC" \
    --maker-key "$MAKER_KEY" --maker-auth webauthn \
    --taker-key "$TAKER_KEY" --taker-auth webauthn \
    --maker-funding "$MAKER_COIN" --taker-funding "$TAKER_COIN" \
    --protocol 1 --timeout 1000 \
    --timeout-payout "$MAKER_OWNER:100" \
    --timeout-payout "$TAKER_OWNER:100"
)
EDGE_ID=$(printf '%s\n' "$OPEN" | awk '$1 == "edge_id" { print $2 }')

# After the open finalizes:
PAYLOAD=$(cargo run -- \
  chain query --rpc "$RPC" latest-block | awk '$1 == "payload" { print $2 }')
cargo run -- \
  chain query --rpc "$RPC" edge --object-id "$EDGE_ID" --payload "$PAYLOAD"

cargo run -- chain close \
  --rpc "$RPC" --edge-id "$EDGE_ID" --kind mutual \
  --payout "$MAKER_OWNER:100" --payout "$TAKER_OWNER:100" \
  --maker-key "$MAKER_KEY" --maker-auth webauthn \
  --taker-key "$TAKER_KEY" --taker-auth webauthn

# After the close finalizes:
cargo run -- \
  chain query --rpc "$RPC" coins-by-owner --owner "$MAKER_OWNER"
cargo run -- \
  chain query --rpc "$RPC" coins-by-owner --owner "$TAKER_OWNER"
```

## Nix

The main outputs are `.#cli` (client, node, gateway and the Catena GPU
runtime) and `.#cli-validator`.
Hellas imports only `catena-lang` from the Catena workspace, pinned to a
published Git revision in `Cargo.toml` and `Cargo.lock`. Nix vendors the same
locked dependency; a sibling Catena checkout is not required.

Enter an x86_64 Linux GPU development shell with:

```sh
nix develop .#rocm --no-write-lock-file  # AMD
nix develop .#cuda --no-write-lock-file  # NVIDIA
```

Catena selects a runtime inside an isolated worker. Use `serve
--gpu-backend auto|hip|cuda` to choose one; `auto` chooses CUDA on a NixOS NVIDIA
host and HIP otherwise.

The NixOS module provisions the matching toolchain and device access:

```nix
services.hellas = {
  enable = true;
  workConfigFile = "/srv/hellas/paid-work.toml"; # passed as --paid-work-config
  passkey = "/srv/hellas/owner.passkey";
  gpuBackend = "cuda"; # or "hip" / "auto"
  contentRoots = [ "/srv/hellas/content" ];
};
```

Keep models and compiler artifacts outside `/nix/store`; they are runtime data.

Fetch providers likewise use runtime files: set `fetchConfigFile` to the JSON
configuration path and `environmentFile` to a systemd environment file holding
provider-local secrets such as `OPENAI_API_KEY`. Do not put either file in a
Nix expression or in the store. In particular, never interpolate the file as a
Nix path and never use `builtins.readFile` on it: both operations expose its
contents during evaluation, before any module assertion or runtime validation
can protect it. Paid Fetch uses metadata-only journals; see
[provider retention](crates/channel/README.md).

On Darwin, the Home Manager launch agent remains network-only but supports the
same runtime-secret boundary:

```nix
programs.hellas = {
  enable = true;
  serve = {
    enable = true;
    workConfigFile = "/Users/alice/.config/hellas/paid-work.toml";
    passkey = "/Users/alice/.config/hellas/owner.passkey";
    fetchConfigFile = "/Users/alice/.config/hellas/fetch.json";
    environmentFile = "/Users/alice/.config/hellas/provider.env";
  };
};
```

Provision the environment file outside Nix and restrict it to the user, with no
group or other permission bits. The runtime wrapper resolves parent symlinks,
rejects the Nix store, opens the final component without following symlinks and
without blocking on special files, then requires that same opened descriptor to
name a regular file owned by the agent's effective user. Its
grammar is deliberately small: blank lines and `#` comments in column one are
allowed; every other line is `NAME=VALUE`, with names matching
`[A-Za-z_][A-Za-z0-9_]*`. Values are literal, so spaces, `#`, and `=` are kept
and quotes, escapes, substitutions, and shell commands have no special
meaning. Duplicate names, malformed lines, CR/NUL bytes, or any failed security
check stop the agent before Hellas runs. The launchd plist contains the absolute
file path, never its contents. As above, never use Nix interpolation or
`builtins.readFile` for this file; validation cannot undo an evaluation-time
secret leak.

Work on the kernel Quint models:

```bash
nix develop .#kernel
nix run .#check-kernel-models
nix run .#check-kernel-model-verify
```

## Docker

The default `docker` output is a network-only node image. It contains no local Catena or
GPU runtime and is tagged `ghcr.io/hellas-ai/hellas:network`. The derivation
streams a Docker archive to stdout:

```bash
$(nix build .#docker --print-out-paths) | docker load
nix run .#docker-push  # network image only
```

GPU images include Catena and the corresponding runtime compiler:

```bash
$(nix build .#docker-cuda --print-out-paths) | docker load
$(nix build .#docker-hip --print-out-paths) | docker load

# NVIDIA with a configured CDI device specification:
docker run --rm --device nvidia.com/gpu=all \
  -v hellas-state:/var/lib/hellas -v /srv/hellas/content:/content:ro \
  ghcr.io/hellas-ai/hellas:cuda --software-root --content-root /content

# AMD:
docker run --rm --device /dev/kfd --device /dev/dri \
  -v hellas-state:/var/lib/hellas -v /srv/hellas/content:/content:ro \
  ghcr.io/hellas-ai/hellas:hip --software-root --content-root /content
```

Both GPU images default to `serve` with their matching backend. The host supplies
the GPU driver and model content stays on runtime volumes. On x86_64 Linux,
`nix run .#docker-push-all` publishes the network, CUDA, and HIP images.

A GPU asset owner uploads verified weights once and execution workers map them
read-only. Worker replacement retains weights; asset pressure recreates the
owner. HIP resident sharing requires version 7.15 or newer.

## Recording and replaying jobs

The gateway keeps no inference cache. `hellas_gateway::start` runs over any
`WorkExecutionBackend`, and text and Fetch events are serializable, so an
application can record and replay jobs by wrapping its work source.

## Dependency maintenance

Available in the development shell:

```bash
cargo audit                # security advisories
cargo outdated --workspace --root-deps-only  # outdated deps
cargo update --workspace   # update Cargo.lock
```

### Optional metrics and OpenTelemetry

The default-off `otel` Cargo feature enables metrics and OTLP export across the
CLI. Default packages, including public musl and Docker builds, omit the metrics
server, `--metrics-port`/`--metrics-addr`, and gateway/executor instruments.
Dependencies may still collect their own telemetry independently. Use an `otel`
build (`cli.override { otel = true; }` or the `docker-otel` image) for metrics.

With that build, `hellas serve --metrics-port 9090` and
`hellas gateway --metrics-port 9091` serve Prometheus text at
`http://127.0.0.1:<port>/metrics`. This unauthenticated listener defaults to
loopback. `--metrics-addr IP` explicitly selects another interface, including
`0.0.0.0` for container scraping. One-shot commands do not start a metrics server.
Scrapes collect executor and gateway instruments from the same meter provider
used for optional OTLP push; both can run together. OTLP environment opt-outs,
including `OTEL_SDK_DISABLED`, leave the requested local listener active.
Iroh endpoint metrics share the response for serve and remote-grant gateways;
paid-pool gateways do not expose their private endpoint.

NixOS exposes `services.hellas.metricsPort` and
`services.hellas.gateway.metricsPort`, with `metricsAddress` beside each port
(default `"127.0.0.1"`). Set `services.hellas.otel.enable = true` to select the
feature-enabled default package, even for local scraping without a collector.
Metrics ports require this setting; custom packages must also enable `otel`.
Chain validators retain their separate `--metrics-bind-address` spelling.

The exported NixOS, nix-darwin and Home Manager modules share `otel` options:

```nix
# NixOS node and gateway:
services.hellas.otel = {
  enable = true;
  collectorEndpoint = "http://127.0.0.1:4318";
  sampleRate = 1.0;
};
# nix-darwin CLI or Home Manager CLI (including Darwin's launchd agent):
programs.hellas.otel.collectorEndpoint = "http://127.0.0.1:4318";
# Validator clusters use services.hellas-chain-validators.<name>.otel.
```

A configured endpoint enables the feature on the module's default package;
`otel.enable = false` selects the build without metrics or OTLP export. Custom
packages remain the caller's choice. `collectorEndpoint` is the standard OTLP
HTTP/protobuf base URL for traces and metrics; the existing `endpoint` option
continues to accept an exact trace URL. Home Manager and nix-darwin scope
variables to `hellas`, rather than enabling unrelated applications.
Home Manager's `programs.hellas.serve` supplies the Darwin user service.
Direct package users can use `cli.override { otel = true; }` (also
`cli-validator`) and the standard `OTEL_*` environment variables.

One CLI SDK lifecycle owns traces and metrics, including validators. Native
operations follow the GenAI Development conventions at
`c88d504ab3d9879f8e50d3cc87e69775e11db234`; these conventions are still evolving.
Hellas-specific work/payment metadata uses `hellas.*`, with W3C TraceContext
in RPC metadata and HTTP headers. Prompts, model output, tool arguments and
credentials are not recorded. Log events stay in the local log sinks, rather
than being duplicated into OTLP. Normal shutdown flushes both providers;
existing forced-exit paths cannot guarantee a final flush.
