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

Catena runs inside an isolated worker. Local daemon backends select CUDA when
an NVIDIA device is present and HIP otherwise. The NixOS module supplies the
matching toolchain and device access.

A declarative HTTP deployment runs the stateless gateway from TOML settings:

```nix
services.hellas.gateway = {
  enable = true;
  settings = {
    models = [ "/srv/models/qwen3.gguf" "gpt-5@openrouter" ];
    upstreams.openrouter = {
      url = "https://openrouter.ai/api";
      key_file = "/run/secrets/openrouter.key";
    };
    listeners.api = { kind = "http"; bind = "127.0.0.1:8080"; zdr = true; };
  };
};
```

The module generates the shared TOML configuration and runs `gateway --config`.
Model packages and API key files remain runtime paths outside the Nix store.
Provision private files for the service user; do not interpolate Nix paths or
call `builtins.readFile` on secrets. The gateway keeps its HTTP bearer in memory;
use `gateway.extraArgs = [ "--wrap" "COMMAND" ];` to pass it to a child.

Private runtime TOML and owner passkeys use systemd `LoadCredential`; ExecStart
receives `%d/hellas-config` and `%d/owner-passkey`, expanded by systemd to private
files readable by the DynamicUser. A TOML file referencing other secret paths
does not grant access to those files. Supply named upstream secrets explicitly:

```nix
services.hellas.gateway.credentials.api = "/run/secrets/openrouter.key";
services.hellas.gateway.settings.upstreams.openrouter.key_file = "credential:api";
```

`credential:NAME` resolves only against systemd's `CREDENTIALS_DIRECTORY` at
runtime. Absolute key paths remain supported when you independently provision
read access for the service user. Home Manager is file-only (`serve.configFile`)
and requires its owner passkey; provision both files readable by that login user.
It does not copy files via systemd or offer a `settings` option.

For a declarative persistent provider:

```nix
services.hellas = {
  enable = true;
  passkey = "/run/secrets/hellas-owner.passkey";
  settings = {
    models = [ "/srv/models/qwen3.gguf" "/srv/models/whisper-tiny" ];
    listeners.work = {
      kind = "iroh";
      port = 31145;
      backends = [ "local" ];
    };
    execution = {
      queue_capacity = 1;
      session_programs = 1;
      session_asset_bytes = 1516744736;
    };
  };
};
```

`settings` becomes TOML passed to `serve --config`. The first start approves
ownership with the provisioned software passkey without a pairing prompt.
Subsequent starts reconcile the complete routing document, retaining identity,
credentials, payment journals, budgets and outstanding duties. Identical
configuration does not advance its revision. Removed routes and listeners are
removed. Execution bounds apply on restart; live control edits cannot change
them. Several model routes share the same serialized local GPU executor.

Put paid offer terms in `settings.paid_policy`, using the policy fields from
[the paid-work guide](paid-gateway.md). The owner authenticates each startup;
unchanged paid terms retain their revision and salt. Removing `paid_policy`
disables new automatic offers while preserving funded channels and recovery.
Configuration and paid terms have separate journal commits; interrupted startup
converges on retry. Startup never requests faucet coins or delegates stake.
Fund the owner and delegate stake to the node's settlement key explicitly as
described in that guide.

Both services also accept `configFile = "/run/hellas.toml"` for an externally
provisioned TOML file. It is mutually exclusive with `settings`. Configure firewall access explicitly
with `networking.firewall.allowedTCPPorts` / `allowedUDPPorts` to match the
listener addresses and ports in TOML. The module rejects
embedded credential `secret`/`access` fields (backend names are unrestricted) and store paths in settings. Use runtime key
files (`upstreams.NAME.key_file`), or a private runtime configFile when raw
credential-bearing backend definitions are necessary. Such a file must be
readable only by its intended service user. With a runtime configFile, provision
its model mounts and any additional service sandbox paths separately.

Without settings/configFile, `services.hellas.enable` retains the interactive
mode: pair its invite, then use `hellas backend`, `hellas route` and
`hellas routes`. An existing paired authority without the local startup
credential is refused by `serve --config`; it is never replaced or recovered
implicitly. Declarative startup's retained local control profile lives at
`HOME/provider/startup-profile/profile.json`; pass it with `--profile` and use
`--control-socket HOME/provider/control.sock` for later operator edits. The next
declarative restart restores the declared document. Preserve the whole home
across restarts; losing the authority journal after initialization fails closed.
The root owner scope and canonical credential use the standard one-year
validity. Renew or explicitly rebind them with the service stopped:

```sh
# Read the current authority revision using admin inspect-offline (see admin.md).
hellas --home /var/lib/hellas/.hellas --passkey /run/secrets/owner.passkey \
  admin rebind-local --expected-revision "$REVISION"
```

This signs the existing authority recovery operation with a fresh normal owner
scope under the same authority ID. It retains accounting, paid terms and channel
duties, advances the generation, and revokes old credentials and administrative
grants; explicitly regrant any required remote administration. It replaces the
one canonical `provider/startup-profile/credential` file, so the retained local
profile and the next declarative startup use the same credential. No startup
implicitly renews or recovers authority. If the process dies or credential
publication fails after recovery commits, inspect the current revision and run
this explicit operation again at that revision; a stale revision is refused.
Never remove journals or startup metadata to work around expiry.

Home Manager can run the stateful service on Darwin:

```nix
programs.hellas = {
  enable = true;
  serve = {
    enable = true;
    passkey = "/Users/alice/.config/hellas/owner.passkey";
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

## Node home format

This cutover uses `hellas.node.identity.v2`, journal v6 and checkpoint v6.
Earlier home formats are rejected at the identity marker before journal replay,
regardless of checkpoint rotation. There is no automatic migration or reset.
Use a new, separately provisioned home for this greenfield format; retain older
homes with their matching binary for any outstanding obligations. Do not delete
journals or change markers to bypass rejection.

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
  ghcr.io/hellas-ai/hellas:cuda

# AMD:
docker run --rm --device /dev/kfd --device /dev/dri \
  -v hellas-state:/var/lib/hellas -v /srv/hellas/content:/content:ro \
  ghcr.io/hellas-ai/hellas:hip
```

Images have the Hellas executable (or CUDA environment wrapper) as Entrypoint,
with `serve --port 31145` as the default Cmd. Override Cmd directly for a
declarative provider, for example `IMAGE serve --config /run/provider.toml`;
the CUDA wrapper forwards those arguments unchanged. By default pair the invite,
then add model routes using paths
inside the container. The host supplies the GPU driver; model packages stay
on runtime volumes. For a stateless container, override Cmd with `gateway --model /content/PACKAGE` and its bearer/wrapper
options.

A GPU asset owner uploads verified weights once and execution workers receive
them as read-only views over GPU IPC. Worker replacement retains weights; asset
pressure recreates the owner.

## Recording and replaying jobs

The daemon core connects gateway routes to `hellas_sdk::ExecutorGateway`, which
runs each request as one job through the same `Executor` as job commands. Text
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
gateways; local-only model backends do not open a provider endpoint.

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
