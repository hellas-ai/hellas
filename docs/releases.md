# Checks and releases

Pull requests into `master` or `devnet` run lints and unit tests on GitHub-hosted
Ubuntu runners. The same checks run after a merge to `master`. Rust outputs
are cached separately per job and dependency lock. Nix dependencies use the
public binary caches. Hydra handles component releases and the explicit
Windows jobset; it does not evaluate pull requests.

```sh
nix run .#check          # PR checks
nix run .#check-lints
nix run .#check-unit
nix run .#check-release  # all test, feature and model-checking checks locally
```

The unit suite includes library and CLI command tests, chain codecs and proof
verification, the pure kernel tests and canonical payment vectors. Live chain
tests, four SDK scenarios that start validator networks, paid end-to-end tests,
full Qwen3/Whisper/Flux compilation and CLI process tests belong to release
validation. `check-model-programs` compiles shipped and upstream programs for
both CUDA and HIP and compares them; CLI and GPU releases require this check.
The unit commands are shared with Hydra in `nix/unit-tests.sh`.

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
| `hellas-cli` | `releaseJobs.cli` | Native Linux packages, portable x86/ARM binaries, network image and RPC WASM library; CLI, SDK, paid-work, feature and discovery tests |
| `hellas-gpu` | `releaseJobs.gpu` | CUDA and HIP images; executor, client-work and provider tests |
| `hellas-consensus` | `releaseJobs.consensus` | Validator package; chain, settlement, validator VM and kernel model checks |

All three also require lints and unit tests. CLI covers x86 and ARM Linux;
GPU and consensus cover x86 Linux. The exact test selection lives in
`nix/releases.nix`. Native archives require their Nix runtime closure; the
musl archives are the portable binaries.

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
