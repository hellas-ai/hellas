{ pkgs, nix-strix-halo }:
let
  inherit (pkgs) lib;
  source = nix-strix-halo;
  readPins =
    name: builtins.fromJSON (builtins.readFile (source + "/pkgs/therock/sources/${name}.json"));
  lock = builtins.fromJSON (builtins.readFile (source + "/flake.lock"));
  # Reuse the source package recipes and their pinned source trees without
  # importing the inference applications or copying their transitive flake lock.
  inputs = builtins.mapAttrs (_: node: builtins.fetchTree node.locked) (
    lib.filterAttrs (name: _: lib.hasPrefix "therock-src-" name) lock.nodes
  );
  targets = import (source + "/pkgs/therock/targets.nix") {
    inherit (import (source + "/lib/rocm-targets.nix")) mkRocmTarget;
  };
  overlay = import (source + "/pkgs/therock") {
    inherit lib;
    inherit (targets) rocmTargets;
    target = targets.defaultRocmTarget;
    therockRocmSources = readPins "rocm";
    therockPythonWheelSources = readPins "python-wheels";
    therockRocmSourcePins = readPins "rocm-source";
    therockRocmSourceTrees = import (source + "/pkgs/therock/sources/source-tree.nix") {
      inherit inputs;
    };
    therockRocmThirdPartySources = readPins "rocm-third-party";
  };
in
# The source scope is architecture-independent. No TheRock binary SDK or
# HSA_OVERRIDE_GFX_VERSION is used; hipcc compiles for the actual provider GPU.
(pkgs.extend overlay).therockRocmPackages
