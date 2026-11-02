# Checks and releases

Pull requests into `master` or `devnet` run lints and unit tests on GitHub-hosted
Ubuntu runners. A native macOS ARM64 job also builds the portable CLI release
artifact, verifies its checksum and signature, checks its architecture and dynamic
libraries, and runs the unpacked executable with a clean environment. It uploads
the archive and checksum as the `hellas-cli-aarch64-darwin` workflow artifact.
The same checks run after a merge to `master`. Rust outputs
are cached separately per job and dependency lock. Nix dependencies use the
public binary caches. Hydra handles component releases and the explicit
Windows jobset; it does not evaluate pull requests.

```sh
nix run .#check          # PR checks
nix run .#check-lints
nix run .#check-unit
nix run .#check-release  # all test, feature and model-checking checks locally
```

The default suite is `cargo test --locked --workspace`: unit tests, lightweight
integration tests and doctests, without local validator networks or model
compilation. Hydra runs it through the standard nixpkgs Cargo check hook.

The `integration-tests` feature on `hellas-chain`, `hellas-sdk` and `hellas-cli`
opts in to separate local-node test modules and complete host-process targets.
Their release checks
(`check-validator`, `check-chain-setup`, `check-sdk-paid-work`, `check-cli`)
enable it explicitly; validator-backed suites run serially. The full integration
suite remains a mandatory PR check (`check-regressions`), using workspace feature
selection plus `hellas-chain/indexer-api` and serial test execution. Indexed
startup and HTTP tests exercise the same production node as the deployed API. Existing tests requiring a GPU, model
files or a special process environment remain individually ignored.

`check-model-programs` explicitly runs the ignored Qwen3/Whisper/Flux compilation
tests for CUDA and HIP; CLI and GPU releases require this check. The consensus
release also runs `check-kernel` with all features, including the Quint replay
and optional authentication suites. Do not use a blanket `--include-ignored`
for default CI: opt in through the appropriate release check instead.

## Independent component releases

CLI and GPU jobsets track `master`; the consensus jobset tracks `devnet`.
Hydra polls these sources and resolves each evaluation to a full commit SHA.
All checks, artifacts and release metadata in that evaluation use that exact
revision, even if the branch advances during the build. Separate source branches
for CLI and GPU are unnecessary.

Each component retains its own validation, artifacts and release channel.
Publishing or deploying one component does not advance the others: promotion
selects a successful evaluation, rather than changing the source branch.

| Jobset in Hydra project `hellas` | Flake output | Artifacts and additional validation |
| --- | --- | --- |
| `hellas-cli` | `releaseJobs.cli` | Native Linux/macOS packages, portable Linux x86/ARM and macOS ARM64 binaries, network image and RPC WASM library; CLI, SDK, paid-work, feature and discovery tests |
| `hellas-gpu` | `releaseJobs.gpu` | CUDA and HIP images; executor, client-work and provider tests |
| `hellas-consensus` | `releaseJobs.consensus` | Validator package; chain, settlement, validator VM and kernel model checks |

All three also require lints and unit tests. CLI covers x86 and ARM Linux and
ARM64 macOS; GPU and consensus cover x86 Linux. CUDA/HIP model compilation
runs on Linux, while the remaining CLI checks run on each release platform.
The exact test selection lives in `nix/releases.nix`. Native Linux archives require
their Nix runtime closure. The musl and Darwin archives run without Nix. Darwin packaging uses the macOS system libiconv and ad-hoc
signs the executable; it is not Developer ID signed or notarized.

```sh
nix build .#releaseJobs.cli.aarch64-darwin.artifacts.native
```

This is the same derivation built by Hydra and the macOS GitHub job. It requires
a native Darwin builder, which Nix/Hydra schedules through their configured
build machines; no SSH packaging or publication script is needed.

Docker is an artifact format: the network image follows the CLI release,
while CUDA/HIP images follow the GPU release. A push to `master` or `devnet`
does not publish any of them. There is no parallel GitHub release workflow.

Hardware comparisons requiring a GPU or private model checkpoints are an
explicit prerequisite to GPU promotion. Building an image and running CPU
tests does not establish that a model executed correctly on hardware.

## Build and promote a release

1. Merge reviewed CLI/GPU changes to `master`, or consensus changes to `devnet`.
   The corresponding Hydra jobsets evaluate automatically. Their source mapping
   lives in infra's `services/ci/hellas-release-jobsets.nix`; no candidate JSON
   or per-component source branch is required.
2. Select a successful component evaluation at the full commit SHA intended for
   release. Its `channel` job must have succeeded: each platform's `release` job
   depends on all its checks and artifacts and rejects Hydra's failed-test
   marker. Release JSON records the source SHA and artifact store paths; archive
   outputs include SHA256 checksums. A standalone CI artifact is useful for
   testing but does not replace the complete component release gate.
3. Record the evaluation/build ID, full SHA, artifact checksums and any required
   GPU hardware results. Keep that build in Hydra so garbage collection cannot
   remove its artifacts. Never resolve a moving branch or latest-successful
   channel again during publication.
4. Publish the existing verified artifacts without rebuilding. An immutable
   release tag names that exact source commit; attach the matching archives and
   checksums. Copy a selected container archive to a commit-specific registry tag
   and record its image digest. Refuse a tag or asset that already names different
   content. Components may publish different successful commits independently.
5. Update deployment pins to the published commit or image digest through infra.
   Building, publishing and deploying are separate actions; a new successful
   build does not change a running deployment.

The repository currently builds Hydra artifacts and CI artifacts; automated
GitHub Release/registry publication is a separate implementation task. Any
publisher must consume a selected successful evaluation under the contract
above, not start another build from `master`.

Hydra's Channels tab exposes a Nix channel for each jobset. Its expression
pins that successful source revision and exposes the component's artifacts.
Deployments still pin an explicit revision or image digest, so a newer channel
build cannot silently change a running environment.

## Deploy through infra

`master` is the integration branch. Chain branches, currently `devnet`, track
consensus rollout. Merge reviewed master changes into the chain branch and
select its successful consensus evaluation; merging alone does not deploy
anything. CLI and GPU promotion independently selects successful `master`
evaluations. Hotfixes follow the same reviewed-source and validation process.

Infra's `hellas-cli` and `hellas-consensus` inputs select their releases
independently. Update only the relevant public pin, for example:

```nix
hellas-cli.url = "github:hellas-ai/hellas/FULL_CLI_COMMIT";
hellas-consensus.url = "github:hellas-ai/hellas/FULL_CONSENSUS_COMMIT";
```

Then run `nix flake update hellas-cli` or `nix flake update hellas-consensus`,
review the lock diff and build the affected hosts with Colmena before applying
the reviewed deployment. Genesis or generation changes are explicit consensus
rollout decisions. GPU deployments select a promoted image digest; infra does
not currently configure a GPU provider host.

Independent release cadence still requires compatible work protocols,
evaluator identities and chain state formats. Check the intended combination
when promoting a component. Keep the previous deployment pins for rollback
where state compatibility permits it.

## Required checks

When adopting this split, change the default-branch ruleset to require `Lints`
and `Unit tests`. Remove the old `Build smoke passed`, `E2E passed` and
`ci/aarch64/required` requirements. Keep the pull-request, review-resolution and
branch-integrity rules. Apply the status-check transition when landing the CI
change, then update other open branches so they report the new unit-test check.
A workflow edit alone does not change GitHub's repository rules.
