# Nix, Docker and NixOS

The main outputs are `.#cli` (the portable client, node and gateway, without
local Catena Compute), `.#cli-validator`, and the `.#docker`, `.#docker-hip`
and `.#docker-cuda` images. The NixOS module and the GPU images build the CLI
with Compute (`cli.override { compute = true; }`), which adds `--local` and
serving Compute jobs.
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
  content = {
    lower = [ "/srv/hellas/content" ];
    index = "resume";
    # Add config/* pin declarations using the IDs and lengths from store index.
  };
};
```

Keep models and compiler artifacts outside `/nix/store`; they are runtime data.

The gateway service takes the same choices as `hellas gateway`: `models`, and
one of `access` (an access file), `pay` with `provider`, or `local`:

```nix
services.hellas.gateway = {
  enable = true;
  models = [ "/srv/hellas/models/qwen3.gguf" ];
  access = "/run/secrets/friend.access";
};
```

A loopback gateway keeps its own authority and bearer under its home, in
`gateway/bearer`. `allowRemote` requires `gatewayProfile`, an explicitly
provisioned authority (see [HTTP gateway authority](admin.md#http-gateway-authority)).

Fetch providers likewise use runtime files: set `fetchConfigFile` to the JSON
configuration path and `environmentFile` to a systemd environment file holding
provider-local secrets such as `OPENAI_API_KEY`. Do not put either file in a
Nix expression or in the store. In particular, never interpolate the file as a
Nix path and never use `builtins.readFile` on it: both operations expose its
contents during evaluation, before any module assertion or runtime validation
can protect it. Paid Fetch uses metadata-only journals; see
[provider retention](../crates/channel/README.md).

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

`nix run .#check` runs the PR lints and unit tests. CLI, GPU execution and
consensus have independent Hydra release jobsets for their heavier tests and
artifacts.

The `unit` check (`nix build .#checks.x86_64-linux.unit`, the PR "Unit tests"
job) runs the workspace tests once under `cargo llvm-cov`. It fails on a
failing test and prints line coverage, which is informational and never fails
the check. Its output holds `lcov.info`, `summary.json` and `summary.txt`.

## Docker

The default `docker` output is a network-only node image. It contains no local Catena or
GPU runtime and is tagged `ghcr.io/hellas-ai/hellas:network`. The derivation
streams a Docker archive to stdout:

```bash
$(nix build .#docker --print-out-paths) | docker load
```

GPU images include Catena and the corresponding runtime compiler:

```bash
$(nix build .#docker-cuda --print-out-paths) | docker load
$(nix build .#docker-hip --print-out-paths) | docker load

# NVIDIA with a configured CDI device specification:
docker run --rm --device nvidia.com/gpu=all \
  -v hellas-state:/var/lib/hellas -v /srv/hellas/content:/content:ro \
  -v /srv/hellas/content.toml:/etc/hellas-content.toml:ro \
  ghcr.io/hellas-ai/hellas:cuda --content-config /etc/hellas-content.toml

# AMD:
docker run --rm --device /dev/kfd --device /dev/dri \
  -v hellas-state:/var/lib/hellas -v /srv/hellas/content:/content:ro \
  -v /srv/hellas/content.toml:/etc/hellas-content.toml:ro \
  ghcr.io/hellas-ai/hellas:hip --content-config /etc/hellas-content.toml
```

The mounted content file should name `/content` as its lower and declare the
Jobs pins needed by the workload. Both GPU images default to `serve` with their matching backend. The host supplies
the GPU driver and model content stays on runtime volumes. Published images are
the Hydra-built artifacts of a commit whose CLI and GPU releases both passed.

A GPU asset owner uploads verified weights once and execution workers receive
them as read-only views over GPU IPC. Worker replacement retains weights; asset
pressure recreates the owner.

## Recording and replaying jobs

The gateway keeps no inference cache. `hellas_gateway::start` runs over any
`WorkExecutionBackend`; the CLI passes `hellas_sdk::ExecutorGateway`, which runs
each request as one job through the same `Executor` as the job commands. Text
and Fetch events are serializable, so an application can record and replay jobs
by wrapping its work source.

## Dependency maintenance

Available in the development shell:

```bash
cargo audit                # security advisories
cargo outdated --workspace --root-deps-only  # outdated deps
cargo update --workspace   # update Cargo.lock
```

## Optional metrics and OpenTelemetry

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
Iroh endpoint metrics share the response for serve and for paid and granted
gateways; a `--local` gateway has no endpoint.

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
