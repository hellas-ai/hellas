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
full Whisper compilation and CLI process tests belong to release validation.
The unit commands are shared with Hydra in `nix/unit-tests.sh`.

## Independent component releases

Each component has its own Hydra jobset, selected revision and channel. A
release or hotfix of one component does not advance the others. They share a
source repository; they do not need to use the same source commit.

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

1. Choose a reviewed, public full commit SHA for the component. In infra,
   set only that component in `services/ci/hellas-release-candidates.json`.
   A `null` candidate disables that jobset. Apply the reviewed CI configuration
   and explicitly evaluate the selected jobset in Hydra. Jobsets do not poll
   a moving branch.
2. Wait for its `channel` job to succeed. Each platform's `release` job
   depends on all its checks and artifacts and rejects Hydra's failed-test
   marker. Release JSON records the source SHA and artifact store paths;
   archive outputs include SHA256 checksums.
3. Record the successful evaluation/build ID, full SHA, artifact checksums and
   any hardware smoke results. Keep the promoted build in Hydra so garbage
   collection cannot remove it. Promotion selects this specific evaluation;
   a channel's latest-successful pointer is not a deployment approval.
4. Distribute the selected artifacts. If publishing a container, copy its
   Docker archive to a commit-specific registry tag and record the resulting
   digest. Deploy by digest. This configuration builds downloadable image
   archives; it does not publish registry tags automatically.

Hydra's Channels tab exposes a Nix channel for each jobset. Its expression
pins that successful source revision and exposes the component's artifacts.
Deployments still pin an explicit revision or image digest, so a newer channel
build cannot silently change a running environment.

## Deploy through infra

`master` is the integration branch. Chain branches, currently `devnet`, track
consensus rollout. Merge reviewed master changes into the chain branch and
select its exact consensus candidate; merging alone does not deploy anything.
CLI and GPU releases can be cut independently from reviewed revisions or
hotfix branches.

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
