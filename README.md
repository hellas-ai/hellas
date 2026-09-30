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

The application owns the meaning of its root. The two currently modelled
shapes intentionally have different trust boundaries:

| Application | Root and trusted computation | Outside that guarantee |
| --- | --- | --- |
| `hellas/catena-gpu-0.0.1`, `causal-lm-0.0.1` | Exact Catena program, entrypoint, content-addressed static objects and borrowed slices, state sizing, vocabulary, capacity, and token-native invocation/result | Model acquisition, provider GPU/backend choice, tokenizer, chat template, text decoding, and API presentation |
| `hellas/fetch-0.0.1`, `codex-responses-0.0.1` or `openai-responses-0.0.1` | A strict stateless Responses field set; typed reconstruction of provider-shaped JSON; `stream=true` and upstream `store=false`; the exact official Codex or OpenAI HTTPS endpoint; no redirects; and SSE response projection | The truth, correctness, and availability of the adversarial upstream service; provider route label; credentials/auth-file location; and access policy |

For causal LM work, the request and transcript bind the manifest, input token
IDs, maximum output, explicit stop IDs, output token IDs, and termination.
`--tokenizer` is a caller-side lens that encodes prompt text and decodes the
verified IDs; it is not part of the Catena kernel claim. Hellas infers no stop
tokens from it.

Fetch is different. Its purpose is to attest the exact transformation around a
remote request, so structuring and destructuring are inside that application's
trusted path rather than presentation performed outside it. This proves which
checks and transformation ran, not that the remote service's claims are true.

A platform-backed Assurance authenticates the Fetch application. The
`ProducerSigned` mode authenticates only the producer key and signed transcript;
it does not authenticate a running binary. The sealed Responses adaptor sends
`store=false` upstream and accepts text and client-executed function tools.

Work is the only execution protocol. This milestone supports payment-funded
channels. Owner and principal grants share the Work protocol, including
`gateway --machine` and sealed Fetch. Delegated project tracks remain a later milestone. Ticket execution, shadow verification, public retained-artifact
retrieval and CacheControl have been removed. Work-side local reproduction
remains available. Accepted paid inputs and results remain in the channel's
recovery/evidence journal, independently of gateway archive settings.

## Causal-LM environments

Human-readable settings live in [`examples/`](examples/). Their paths are
local acquisition hints; canonical environment bytes contain only identities,
lengths, and ABI data.

```sh
hellas-cli environment build \
  --program model.hex \
  --settings examples/smollm2.environment.toml \
  --out smollm2.environment

hellas-cli environment inspect --environment smollm2.environment

# Prove one environment and all of its referenced content are provider-ready.
hellas-cli environment verify \
  --environment smollm2.environment \
  --content-root /srv/hellas/content \
  --content-index /var/lib/hellas/content.index
```

For `gateway`, the caller selects the environment trust anchor before
any route starts. By default, the exact local `--environment` file bytes are
that anchor and the CLI derives their manifest ID. When a manifest ID was
distributed separately, pass `--manifest-id <CONTENT_ID>`; a file deriving
a different ID is rejected before network or GPU work. A provider never selects
either value.

A provider indexes ordinary runtime files and can accept any locally
satisfiable supported environment; it need not register a model name:

```sh
hellas-cli --software-root serve \
  --work-config /run/hellas/work.json \
  --content-root /srv/hellas/content
```

Work execution strictly decodes the submitted manifest. The first binding opens
its root by exact local content ID and verifies every declared program/static
object; later executions for that exact manifest may reuse the immutable verified
binding without reopening or rehashing those files. Binding does not acquire content. The authorized worker is the final availability and integrity
boundary: before nonresident content enters the safe runtime, it reopens the
descriptor and enforces the exact ID and length; an already-resident exact
mapping is reused. The provider then compiles the Catena source for its visible
GPU device. Verified static files are lent by descriptor to a bounded
persistent safe-runtime session, so an already prepared program and weights are
reused across requests until the session is recycled or the service restarts.
There is no client-supplied `gfx` target or provider architecture allow-list.
Providers independently bound compilation with `--gpu-compile-timeout-secs`
and each complete generation with `--gpu-execution-timeout-secs`; expiry kills
the isolated worker process group and the next request starts a fresh session.
`--gpu-max-generation-capacity` is additionally capped at 524288 tokens so a
token transcripts stay within the canonical artifact size bound.

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
Use `serve --fetch-config FILE --work-config FILE` to mount paid execution.
See [paid Work](crates/work/README.md) for channel configuration and
[HTTPS Fetch](crates/providers/HTTPS.md) for provider credentials and egress.

## HTTP gateway

For upstream APIs, [HTTP Fetch routes](docs/http-gateway.md) preserve the vendor's
request, response and streaming formats. CLI gateways archive payloads by default;
`--zdr` or `x-hellas-zdr: true` disables application payload persistence.

The causal-LM gateway requires the same canonical environment and an explicit
presentation tokenizer. `--model` is only an API response label; when omitted,
the manifest ID is used.

Configure a funded pool using the [paid gateway guide](docs/paid-gateway.md),
then pass `--paid-work-config POOL` together with `--environment` and
`--tokenizer`. The former in-process local route awaits owner grant funding.

It binds loopback by default. Non-loopback listening requires `--allow-remote`
and `--bearer-token-file FILE`; the private credential file is created once and
reused across restarts. Without a file, a fresh credential is shown on the
controlling terminal. The causal-LM backend accepts plain text at
`/v1/completions` and `/v1/responses`. Set `--chat-template` to enable the shared
model adapter for chat, reasoning and tool calls supported by that model.
The proxy Responses backend retains its explicit upstream semantics.
The unpaid attested Fetch Responses backend awaits grant funding. `--responses-backend` changes only `/v1/responses`; every other
route remains bound to the causal-LM environment, so `--environment` and
`--tokenizer` are still required.

The exposed routes are:

```text
POST /v1/completions
POST /v1/responses
POST /v1/chat/completions
POST /v1/messages
```

Monitor discovery and peer health with `hellas-cli monitor --timeout-secs 30`.

## Chain

The `chain` feature provides `chain query`, `chain open`, and `chain close`.
The `indexer` feature adds `chain indexer follow`; the `validator` feature adds
`chain validator config`, `chain validator run`, and
`chain validator check-config`.

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
secp256k1 keys can own stored coins. Legacy `Transfer` and `MergeCoin`
verification remains P-256-only, and genesis owner strings must decode as
P-256 keys when the validator config is loaded.

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
  cargo run --no-default-features --features chain -- chain open \
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
PAYLOAD=$(cargo run --no-default-features --features chain -- \
  chain query --rpc "$RPC" latest-block | awk '$1 == "payload" { print $2 }')
cargo run --no-default-features --features chain -- \
  chain query --rpc "$RPC" edge --object-id "$EDGE_ID" --payload "$PAYLOAD"

cargo run --no-default-features --features chain -- chain close \
  --rpc "$RPC" --edge-id "$EDGE_ID" --kind mutual \
  --payout "$MAKER_OWNER:100" --payout "$TAKER_OWNER:100" \
  --maker-key "$MAKER_KEY" --maker-auth webauthn \
  --taker-key "$TAKER_KEY" --taker-auth webauthn

# After the close finalizes:
cargo run --no-default-features --features chain -- \
  chain query --rpc "$RPC" coins-by-owner --owner "$MAKER_OWNER"
cargo run --no-default-features --features chain -- \
  chain query --rpc "$RPC" coins-by-owner --owner "$TAKER_OWNER"
```

## Nix

The main outputs are `.#cli` (network client/node/gateway), `.#cli-catena`
(x86_64 Linux plus the Catena safe GPU runtime), and `.#cli-validator`.
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
  workConfigFile = "/srv/hellas/work.json";
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
[provider retention](crates/work/README.md).

On Darwin, the Home Manager launch agent remains network-only but supports the
same runtime-secret boundary:

```nix
programs.hellas = {
  enable = true;
  serve = {
    enable = true;
    workConfigFile = "/Users/alice/.config/hellas/work.json";
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

## Inference cache and reproducible agent runs

The gateway retains its local inference archive: `--output-cache off`, `record`
(reuse complete successful results and record misses), or `replay-only` (fail
on misses without execution). Paid completion and payment acknowledgement finish
before a successful result is recorded. Proxy requests also support recording.
The executor's separate replay cache and the cache administration RPC/CLI have
been removed.

The archive uses the existing Hellas store (`--store-dir`, `HELLAS_STORE_DIR`,
or `~/.hellas/store`). One process owns a writable index. Stop the writer before
copying a complete store snapshot for offline replay. Recording persists payloads
and is incompatible with gateway ZDR mode. Agent tool execution is not cached.

```sh
hellas-cli --output-cache record gateway --responses-backend proxy --wrap opencode
hellas-cli --output-cache replay-only gateway --responses-backend proxy --wrap opencode
```

For a Linux Nix agent build, use the overlay's `pkgs.hellasLib.agent` helpers:

```nix
let
  agent = pkgs.hellasLib.agent;
  inputs = {
    name = "agent-change";
    workspace = ./source;
    prompt = builtins.readFile ./prompt.txt;
    model = "your-provider-model";
    hellas = pkgs.hellas.cli;
    opencode = pkgs.opencode;
    packages = [ pkgs.rustc pkgs.cargo ]; # tools available to the agent
    gatewayArgs = [ "--responses-backend" "proxy" ];
  };
in {
  record = agent.mkAgentRecord inputs;
  result = agent.mkAgentRun (inputs // { cache = ./agent-recordings; });
}
```

Run the recorder executable with a writable store directory outside the Nix
build, with provider credentials in its runtime environment. Stop the writer, copy a complete store snapshot,
and use it as `cache`. `mkAgentRun` starts a replay-only gateway inside the
sandbox, runs OpenCode, and returns its resulting workspace. Both phases use
`/build/workspace`, the same pinned tools/configuration, and an explicit system
prompt `date` (default `1970-01-01`). Changing inputs can produce a cache miss;
re-record them instead of giving the build network access. A replay reruns
tools and is only reproducible when those tools are deterministic too.

The helper uses OpenCode's generic OpenAI Responses client. Its endpoint must
accept that request shape; the stricter sealed `codex-responses` Fetch contract
is not a drop-in target. A zero OpenCode exit status alone is not success: the
runner also requires a completed session and rejects error events.

Recordings and generated files can contain private source or model output.
Do not put credentials in Nix expressions, and do not publish recordings
without reviewing them: Nix store contents are normally readable by all local
users.

## Dependency maintenance

Available in the development shell:

```bash
cargo audit                # security advisories
cargo outdated --workspace --root-deps-only  # outdated deps
cargo update --workspace   # update Cargo.lock
```

### Optional OpenTelemetry

The `otel` Cargo feature is opt-in across the CLI (including Fetch, node,
gateway, indexer and validator commands). Default Nix packages, including
public musl builds, disable Hellas telemetry exporters. Request instrumentation
uses shared enabled/no-op implementations; ordinary operational logs remain.
Transitive dependencies still include metrics collection and telemetry SDK crates;
disabling `otel` does not remove those dependencies.

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
`otel.enable = false` explicitly selects the build without telemetry. Custom
packages remain the caller's choice. `collectorEndpoint` is the standard OTLP
HTTP/protobuf base URL for traces and metrics; the existing `endpoint` option
continues to accept an exact trace URL. Home Manager and nix-darwin scope
variables to `hellas-cli`, rather than enabling unrelated applications.
Home Manager's `programs.hellas.serve` supplies the Darwin user service.
Direct package users can use `cli.override { otel = true; }` (also
`cli-catena` and `cli-validator`) and the standard `OTEL_*` environment variables.

One CLI SDK lifecycle owns traces and metrics, including validators. Native
operations follow the GenAI Development conventions at
`c88d504ab3d9879f8e50d3cc87e69775e11db234`; these conventions are still evolving.
Hellas-specific work/payment metadata uses `hellas.*`, with W3C TraceContext
in RPC metadata and HTTP headers. Prompts, model output, tool arguments and
credentials are not recorded. Log events stay in the local log sinks, rather
than being duplicated into OTLP. Normal shutdown flushes both providers;
existing forced-exit paths cannot guarantee a final flush.
