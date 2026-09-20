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
it does not authenticate a running binary. The Responses-facing `store` switch
controls Hellas Courtesy transcript retention. The upstream call made by the
attested app is always stateless and sends `store=false`. This first sealed adaptor accepts text
and client-executed function tools; it rejects provider-account references,
provider-side tools, file/image inputs, and unknown top-level fields.

Retention is opt-in. `--retain` (or a request-level `retain=true` / `store=true`)
publishes prompt- and token-bearing artifacts through content-addressed Courtesy
`GetArtifact`; a digest is an address, not an authorization capability. Omission
keeps the execution ephemeral. This is not a deletion promise for an accepted paid job: the signed
prepared input remains in that channel's recovery/evidence journal as required
to resume safely after a crash.

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

For `llm` and `gateway`, the caller selects the environment trust anchor before
any route starts. By default, the exact local `--environment` file bytes are
that anchor and the CLI derives their manifest ID. When a manifest ID was
distributed separately, pass `--manifest-id <CONTENT_ID>`; a file deriving
a different ID is rejected before network or GPU work. A provider never selects
either value.

A provider indexes ordinary runtime files and can accept any locally
satisfiable supported environment; it need not register a model name:

```sh
hellas-cli --software-root serve \
  --execute-policy any \
  --content-root /srv/hellas/content
```

`QuoteTokens` strictly decodes the submitted manifest. The first binding opens
its root by exact local content ID and verifies every declared program/static
object; later quotes for that exact manifest may reuse the immutable verified
binding without reopening or rehashing those files. Quoting neither fetches nor
compiles. The authorized worker is the final availability and integrity
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
retained token transcript fits Hellas's 4 MiB unary artifact transport.

Indexed provider content is an immutable local-cache assumption. Hellas pins
the verified read-only descriptor and detects path/inode replacement; it does
not defend against a separate local process that already holds a writable
descriptor to the same inode and mutates it concurrently.

## Sealed Fetch

Fetch route names are operator-defined routing labels. The sealed destination
selects the trusted adaptor, fixed official endpoint, no-redirect HTTP driver,
and response projector as one unit. A configuration cannot supply a URL or
claim a different adaptor identity.

For an OpenAI Responses route, first create the caller identity and obtain its
producer public key:

```sh
hellas-cli --identity caller.identity --software-root identity init
CALLER_KEY=$(hellas-cli --identity caller.identity producer-key show |
  awk '$1 == "public_key:" { print $2 }')
export CALLER_KEY
export OPENAI_API_KEY='<provider-local credential>'
```

Write `fetch.json`; the model/output limits shown are optional:

```json
{
  "routes": [{
    "service": "openai",
    "method": "responses",
    "destination": {
      "type": "openai-responses",
      "api_key_env": "OPENAI_API_KEY"
    },
    "capabilities": {
      "models": ["gpt-5.5"],
      "max_output_tokens": 4096
    }
  }],
  "callers": [{
    "public_key": "REPLACE_WITH_CALLER_KEY",
    "routes": [{
      "service": "openai",
      "method": "responses",
      "models": ["gpt-5.5"],
      "max_output_tokens": 512
    }]
  }]
}
```

Replace `REPLACE_WITH_CALLER_KEY` with `$CALLER_KEY`, then start the provider
and obtain its node and enrollment IDs through a trusted channel:

```sh
hellas-cli --identity provider.identity --software-root identity init
NODE_ID=$(hellas-cli --identity provider.identity identity show-node-id)
ENROLLMENT_ID=$(hellas-cli --identity provider.identity identity show-enrollment-id)

hellas-cli --identity provider.identity --software-root serve \
  --port 49152 \
  --fetch-config fetch.json
```

The OpenAI sealed manifest ID is
`a4ff1dbe22fe5d6888258bd95d21a288855c11d40b59c86ad834ab747033e8e8`.
Run one strict provider-shaped request from another terminal:

```sh
hellas-cli --identity caller.identity --software-root fetch "$NODE_ID" \
  --node-addr 127.0.0.1:49152 \
  --provider "$ENROLLMENT_ID" \
  --service openai \
  --method responses \
  --execution-environment openai-responses \
  --payload '{"model":"gpt-5.5","input":"Say hello","stream":true,"store":false,"max_output_tokens":32}'
```

Output is JSON Lines of semantic response events followed by one terminal
event; raw upstream SSE is never the signed result. The caller's exact input
bytes are signed, but the trusted app parses and reconstructs a fresh upstream
body before egress. Open, ticket creation, execution, and output-key
verification all remain on the same confidentially opened transport.

The Codex alternative uses destination type `codex-responses`, a local
`auth_path` populated by `hellas-cli codex-auth login`, and sealed manifest ID
`82ebed7724b614bfcca6082924710098821cafc95789f136f770667e16ef9785`.
In both cases, `ProducerSigned` proves only the key and transcript. Claiming the
trusted app itself requires a platform-backed assurance.

## HTTP gateway

The gateway requires the same canonical causal-LM environment and an explicit
presentation tokenizer. `--model` is only an API response label; when omitted,
the manifest ID is used.

```sh
hellas-cli --software-root gateway \
  --local \
  --environment smollm2.environment \
  --content-root /srv/hellas/content \
  --tokenizer /srv/hellas-presentation/tokenizer.json \
  --model smollm2-135m
```

It binds loopback and shows a fresh bearer credential once on its controlling
terminal. The Hellas causal-LM backend accepts plain text at
`/v1/completions` and simple text input at `/v1/responses`. It rejects chat,
tool, and reasoning structures because no trusted or implicit chat template
exists. The proxy and attested Fetch Responses backends have their own explicit
semantics. `--responses-backend` changes only `/v1/responses`; every other
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

Catena selects a usable CUDA or HIP runtime inside its isolated worker. Use
`serve --gpu-backend auto|hip|cuda` to override selection. GPU visibility follows
`CUDA_VISIBLE_DEVICES` or `HIP_VISIBLE_DEVICES`.

The NixOS provider module configures toolchains, scratch directories, and device
access for local execution. Set `gpuBackend = "cuda"` for NVIDIA or `"hip"` for
AMD; automatic configuration includes CUDA when the NixOS NVIDIA driver is enabled:

```nix
services.hellas = {
  enable = true;
  openFirewall = true;
  executePolicy = "any";
  contentRoots = [ "/srv/hellas/content" ];
  extraArgs = [ "--software-root" ];
};
```

Model weights, Catena programs, environment files, tokenizers, and generated
compiler artifacts are runtime data. Keep them outside `/nix/store`; the
module rejects store paths for these options. A provider chooses its actual
GPU device at execution time rather than baking a client-selected target into
the environment.

Fetch providers likewise use runtime files: set `fetchConfigFile` to the JSON
configuration path and `environmentFile` to a systemd environment file holding
provider-local secrets such as `OPENAI_API_KEY`. Do not put either file in a
Nix expression or in the store. In particular, never interpolate the file as a
Nix path and never use `builtins.readFile` on it: both operations expose its
contents during evaluation, before any module assertion or runtime validation
can protect it. Retained Fetch evidence is bounded across both
completed transcripts and indeterminate running markers by
`fetchRetainedTranscriptCapacity` (default 1024; zero disables new retention).
`fetchReplayMaxInFlight` separately bounds replay consumers (default 16), and a
slot remains occupied until its event stream is drained or dropped. The
retention capacity is persisted per transcript-store root so processes sharing
one root cannot disagree. Stop every such process before changing the capacity
or removing its metadata; existing transcripts and running markers are never
deleted, and an already over-cap root still starts and replays while refusing
new retention.

On Darwin, the Home Manager launch agent remains network-only but supports the
same runtime-secret boundary:

```nix
programs.hellas = {
  enable = true;
  serve = {
    enable = true;
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

Retained Evaluate artifacts are separately bounded by
`evaluateRetainedExecutionCapacity` (default 1024; zero disables new retained
completions). Each unique execution reserves one persistent slot before its
graph is published; a crash can leave that slot and up to eight canonical
objects behind, but cannot grow the store past the configured execution bound.
The Evaluate root is exclusively locked for the provider lifetime, and its
capacity metadata must match on every restart.

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
nix run .#docker-push-all
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
the GPU driver; model content stays on runtime volumes. Publish `31145/udp` when
accepting external connections. NVIDIA hosts using the conventional container
runtime can use `--gpus all` instead of the CDI device argument.

Catena uploads verified weights once into a dedicated GPU asset-owner process.
Execution workers share read-only VRAM mappings and retain private KV caches and
scratch memory. Worker replacement preserves cached weights; asset-capacity
pressure recycles the owner as well. The session asset limit bounds cached weight
payloads; leave additional VRAM for allocation granularity, contexts, and state.
The HIP image uses the newer ROCm stack pinned from `nix-strix-halo`; resident
sharing requires HIP 7.15 or newer. Source weight files remain read-only.

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
public musl builds, omit the telemetry SDK/exporters. Request instrumentation
uses shared enabled/no-op implementations; ordinary operational logs remain.
Commonware is pinned to our four-file optional-telemetry patch so it does not
silently pull a second SDK into these builds.

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
