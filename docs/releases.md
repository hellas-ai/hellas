# Checks and chain releases

Pull requests into `master` or `devnet` run lints and unit tests. The same
checks run after a merge to `master`. Hydra's `required` aggregate contains
lints and unit tests on each supported Linux architecture; it does not build
release packages, containers or VMs.

```sh
nix run .#check          # PR checks
nix run .#check-lints
nix run .#check-unit
nix run .#check-release  # full test, feature and model-checking suite
```

The unit suite includes library and CLI command tests, chain codecs and proof
verification, the pure kernel tests and canonical payment vectors. Live chain
tests, the four SDK scenarios that start validator networks, paid end-to-end
tests, full Whisper compilation and CLI process tests run in the release
suite. The test commands are shared with Hydra in `nix/unit-tests.sh`.

## Promote a chain release

`master` is the integration branch. Each chain has a release branch; currently
the supported release branch is `devnet`. Promote reviewed changes by merging
`master` into `devnet`. Do not rebase an existing chain branch or move its head
backward. When first establishing the remote branch, use the chosen reviewed
master revision rather than an old local branch with the same name.

A push to `devnet` starts the **Release** workflow. It can also be rerun with
`workflow_dispatch` on `devnet`; other refs are refused. It runs:

- The full test and feature matrix, including real chain and paid-work tests.
- Native/validator packages, portable x86/ARM binaries and WASM builds.
- NixOS VM tests against those packages.
- Network, CUDA and HIP container builds.

Portable artifacts carry the source commit in their filenames. Images publish
only after checks, builds and VM tests pass, as
`ghcr.io/hellas-ai/hellas:sha-COMMIT-{network,cuda,hip}`. The publishing job records
each registry digest in its summary. PRs and pushes to `master` publish no
images. Release runs are serialized per branch; an active run can finish when
a newer revision is pushed.

Hardware model comparisons requiring private checkpoints or a GPU remain
explicit release validation on the configured GPU host; building a GPU image
does not claim that a model has executed on hardware.

## Deploy through infra

Deployment is a separate operation in `../infra`, after the release succeeds:

1. Choose the exact successful `devnet` commit and record any required hardware
   smoke results. Do not substitute a newer branch head.
2. Update infra's `node` input to that public Hellas revision and update its
   lock file. Validators and paid providers must use the same chosen release.
3. Review the infra diff, including any explicit genesis/generation change,
   and build the affected hosts with Colmena.
4. Apply the reviewed infra change to the intended hosts and check service
   health. Retain the previous infra revision for rollback where the chain's
   state format permits it.

The Hellas workflow does not deploy hosts or update infra's pin automatically.
Infra must resolve the published revision, not a developer's local Git path.
For example, set `node.url = "github:hellas-ai/hellas/RELEASE_COMMIT"` in
infra's `flake.nix`, replacing `RELEASE_COMMIT` with the validated full SHA,
then run `nix flake update node` there and review the resulting lock diff.

## Required checks

When adopting this split, change the default-branch ruleset to require `Lints`,
`Unit tests` and `ci/aarch64/required`. Remove the old `Build smoke passed` and
`E2E passed` requirements; those jobs now belong to release validation.
Keep the pull-request, review-resolution and branch-integrity rules. Apply the
status-check transition when landing the CI change, then update other open
branches so they report the new unit-test check. A workflow edit alone does
not change GitHub's repository rules.
