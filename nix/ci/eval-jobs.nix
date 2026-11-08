# Evaluates the Hydra and release jobs without building anything and returns
# the names of the jobs that fail to evaluate. Module-eval tests are
# assertions forced by evaluation, so a stale one shows up here before merge.
# The GPU release jobs are left to Hydra: evaluating them fetches several GB
# of ROCm sources, which takes longer than a PR check should.
{ flake }:
let
  inherit (flake.inputs.nixpkgs) lib;
  jobs =
    path: value:
    if lib.isDerivation value then
      lib.optional (!(builtins.tryEval value.drvPath).success) path
    else if builtins.isAttrs value then
      lib.concatLists (lib.mapAttrsToList (name: jobs "${path}.${name}") value)
    else
      [ ];
in
jobs "hydraJobs" flake.hydraJobs
++ jobs "releaseJobs.cli" flake.releaseJobs.cli
++ jobs "releaseJobs.consensus" flake.releaseJobs.consensus
