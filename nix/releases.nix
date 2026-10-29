{
  self,
  pkgs,
  lib,
  system,
  nativePkg,
  nativePackages,
  crossPackages,
  linuxOutputs,
  hydraLints,
  hydraUnit,
  hellasRpcWasm,
  ci,
}:
let
  x86 = system == "x86_64-linux";
  revision = self.rev or self.dirtyRev or "unknown";
  archive =
    name: package:
    pkgs.runCommand "hellas-${name}-${revision}" { } ''
      mkdir -p "$out/nix-support"
      tar --dereference -C ${package} -czf "$out/hellas-${name}-${revision}.tar.gz" .
      cd "$out"
      sha256sum *.tar.gz > SHA256SUMS
      echo "file binary-dist $out/hellas-${name}-${revision}.tar.gz" > nix-support/hydra-build-products
    '';
  image =
    backend:
    let
      stream = linuxOutputs.packages.${if backend == "network" then "docker" else "docker-${backend}"};
    in
    pkgs.runCommand "hellas-image-${backend}-${revision}" { } ''
      set -o pipefail
      mkdir -p "$out/nix-support"
      ${stream} | gzip -n -1 > "$out/hellas-${backend}-${revision}.tar.gz"
      cd "$out"
      sha256sum *.tar.gz > SHA256SUMS
      echo "file binary-dist $out/hellas-${backend}-${revision}.tar.gz" > nix-support/hydra-build-products
    '';
  specifications = {
    cli = {
      checks = [
        "cli"
        "cloud"
        "client-work"
        "http-fetch"
        "rpc-work"
        "sdk-paid-work"
        "clippy-features"
        "wasm-rpc"
        "wasm-chain"
        "wasm-xet"
      ];
      artifacts = {
        native = archive "cli-${system}" nativePackages.cli;
      }
      // lib.optionalAttrs x86 {
        static-x86_64 = archive "cli-x86_64-linux-musl" crossPackages.cross-x86_64-linux-musl-cli;
        static-aarch64 = archive "cli-aarch64-linux-musl" crossPackages.cross-aarch64-linux-musl-cli;
        network-image = image "network";
        wasm = archive "rpc-wasm" hellasRpcWasm;
      };
      vms = lib.optionals x86 [
        "basic"
        "discovery-monitor"
        "provider-content-index-eval"
      ];
    };
    gpu = {
      checks = [
        "executor"
        "client-work"
        "http-fetch"
      ];
      artifacts = {
        cuda-image = image "cuda";
        hip-image = image "hip";
      };
      vms = [ ];
    };
    consensus = {
      checks = [
        "chain-features"
        "chain-block-view"
        "chain-indexer-lint"
        "chain-validator-lint"
        "chain-work-watcher"
        "rpc-chain"
        "validator"
        "chain-setup"
        "kernel"
        "kernel-models"
        "kernel-model-run"
        "kernel-model-verify"
        "kernel-fixture-freshness"
      ];
      artifacts = {
        validator = archive "consensus-${system}" nativePackages.cli-validator;
      };
      vms = [
        "chain-validator-follower"
        "chain-edge-settlement"
        "validator-module-eval"
      ];
    };
  };
  makeRelease =
    component: spec:
    let
      validation = nativePkg.mkHellasPackage {
        pname = "hellas-${component}-validation";
        cargoBuildType = "debug";
        buildPhase = ''
          runHook preBuild
          ${lib.concatMapStringsSep "\n" (name: lib.getExe ci.checks.${name}) spec.checks}
          runHook postBuild
        '';
        doCheck = false;
        installPhase = ''
          mkdir -p "$out"
          touch "$out/passed"
        '';
      };
      tests = lib.genAttrs spec.vms (name: linuxOutputs.nixosTests.${name});
      required = pkgs.releaseTools.aggregate {
        name = "hellas-${component}-${system}-tested";
        constituents = [
          validation
          hydraUnit
        ]
        ++ lib.attrValues hydraLints
        ++ lib.attrValues spec.artifacts
        ++ lib.attrValues tests;
      };
      manifest = pkgs.writeText "hellas-${component}-release.json" (
        builtins.toJSON {
          inherit component revision system;
          artifacts = lib.mapAttrs (_: toString) spec.artifacts;
        }
      );
    in
    {
      inherit validation tests required;
      inherit (spec) artifacts;
      release = pkgs.runCommand "hellas-${component}-${system}-release" { } ''
        test -e ${required}
        test ! -e ${required}/nix-support/failed
        mkdir -p "$out/nix-support"
        cp ${manifest} "$out/release.json"
        echo "file json $out/release.json" > "$out/nix-support/hydra-build-products"
      '';
    };
in
lib.mapAttrs makeRelease (lib.filterAttrs (name: _: x86 || name == "cli") specifications)
