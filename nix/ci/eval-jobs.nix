# Evaluates every Hydra, release and Windows job without building anything and
# returns the names of the jobs that fail to evaluate. Module-eval tests are
# assertions forced by evaluation, so a stale one shows up here before merge.
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
++ jobs "releaseJobs" flake.releaseJobs
++ jobs "windowsJobs" flake.windowsJobs
