{
  self,
  pkgs,
  lib,
  system,
  nativePackages,
  crossPackages,
  linuxOutputs,
  hydraLints,
  buildChecks,
  hellasRpcWasm,
}:
let
  x86 = system == "x86_64-linux";
  darwin = pkgs.stdenv.hostPlatform.isDarwin;
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
  # Keep the normal Nix package intact. Only the downloadable Darwin binary
  # uses macOS's libiconv; reject new non-system dependencies instead of shipping
  # an archive that happens to work on the builder's Nix installation.
  portableDarwin =
    pkgs.runCommand "hellas-cli-portable-${system}"
      {
        nativeBuildInputs = [ pkgs.darwin.cctools ];
      }
      ''
        mkdir -p "$out/bin"
        cp ${nativePackages.cli}/bin/hellas "$out/bin/hellas"
        chmod u+w "$out/bin/hellas"
        otool -L "$out/bin/hellas" | awk 'NR > 1 { print $1 }' > dependencies
        while IFS= read -r dependency; do
          case "$dependency" in
            /nix/store/*/lib/libiconv.2.dylib)
              install_name_tool -change "$dependency" /usr/lib/libiconv.2.dylib "$out/bin/hellas"
              ;;
            /usr/lib/*|/System/Library/*) ;;
            *) echo "Unsupported portable Darwin dependency: $dependency" >&2; exit 1 ;;
          esac
        done < dependencies
        source ${pkgs.darwin.signingUtils}
        sign "$out/bin/hellas"
        "$out/bin/hellas" --version
        "$out/bin/hellas" --help > /dev/null
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
  thinChecks = [
    "cli"
    "cloud"
    "client-work"
    "http-fetch"
    "rpc-work"
    "sdk-paid-work"
  ];
  # Promotion gates share the existing jobsets and exact source revision. Keep
  # archive and image dependencies out of the native package gates.
  promotion = {
    cli = {
      nix-thin = {
        checks = thinChecks;
        outputs = {
          thin = nativePackages.cli;
        };
      };
    }
    // lib.optionalAttrs (x86 || darwin) {
      standalone = {
        checks = thinChecks;
        artifacts =
          if darwin then
            [ "portable-aarch64" ]
          else
            [
              "portable-x86_64"
              "portable-aarch64"
              "installer"
            ];
      };
    }
    // lib.optionalAttrs x86 {
      wasm = {
        checks = [
          "wasm-rpc"
          "wasm-chain"
          "wasm-xet"
        ];
        artifacts = [ "wasm" ];
      };
      network = {
        checks = thinChecks;
        artifacts = [ "network-image" ];
      };
    };
    gpu = lib.genAttrs [ "cuda" "hip" ] (backend: {
      checks = [
        "executor"
        "client-work"
        "http-fetch"
        "rpc-work"
        "sdk-paid-work"
      ];
      artifacts = [ "${backend}-image" ];
      outputs = {
        "cli-${backend}" = linuxOutputs.packages."cli-${backend}";
      };
    });
    consensus.l1 = {
      includeTests = true;
      artifacts = [ "validator" ];
      outputs = {
        l1 = nativePackages.cli-validator;
      };
    };
  };
  specifications = {
    cli = {
      dependencies =
        lib.optionalAttrs (x86 || darwin) { cli = nativePackages.cli.cargoArtifacts; }
        // lib.optionalAttrs x86 {
          portable-x86_64 = crossPackages.cross-x86_64-linux-musl-cli.cargoArtifacts;
          portable-aarch64 = crossPackages.cross-aarch64-linux-musl-cli.cargoArtifacts;
          wasm = hellasRpcWasm.cargoArtifacts;
        };
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
      artifacts =
        lib.optionalAttrs darwin {
          portable-aarch64 = archive "${system}-portable" portableDarwin;
        }
        // lib.optionalAttrs x86 {
          installer = pkgs.runCommand "hellas-installer-${revision}" { } ''
            mkdir -p "$out"
            cp ${../install.sh} "$out/install.sh"
            cd "$out"
            sha256sum install.sh > SHA256SUMS
          '';
          portable-x86_64 = archive "x86_64-linux-portable" crossPackages.cross-x86_64-linux-musl-cli;
          portable-aarch64 = archive "aarch64-linux-portable" crossPackages.cross-aarch64-linux-musl-cli;
          network-image = image "network";
          wasm = archive "rpc-wasm" hellasRpcWasm;
        };
      vms = lib.optionals x86 [
        "basic"
        "provider-content-eval"
      ];
    };
    gpu = {
      dependencies.cli-compute = (nativePackages.cli.override { compute = true; }).cargoArtifacts;
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
      dependencies = {
        validator = nativePackages.cli-validator.cargoArtifacts;
        validator-otel = (nativePackages.cli-validator.override { otel = true; }).cargoArtifacts;
      };
      checks = [
        "telemetry-collector"
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
      checks =
        hydraLints
        // lib.genAttrs (
          [
            "unit"
            "feature-targets"
          ]
          ++ spec.checks
        ) (name: buildChecks.${name});
      tests = lib.genAttrs spec.vms (name: linuxOutputs.nixosTests.${name});
      promotionLanes = promotion.${component};
      promotionOutputs = lib.mergeAttrsList (
        map (lane: lane.outputs or { }) (lib.attrValues promotionLanes)
      );
      promotionGates = lib.mapAttrs (
        laneName: lane:
        pkgs.releaseTools.aggregate {
          name = "hellas-${laneName}-${system}-tested";
          constituents =
            map (name: buildChecks.${name}) (lane.checks or spec.checks)
            ++ map (name: spec.artifacts.${name}) (lane.artifacts or [ ])
            ++ lib.attrValues (lane.outputs or { })
            ++ lib.optionals (lane.includeTests or false) (lib.attrValues tests);
        }
      ) promotionLanes;
      required = pkgs.releaseTools.aggregate {
        name = "hellas-${component}-${system}-tested";
        constituents =
          lib.attrValues (if component == "consensus" then removeAttrs checks [ "unit" ] else checks)
          ++ lib.attrValues spec.artifacts
          ++ lib.attrValues tests;
      };
      manifest = pkgs.writeText "hellas-${component}-release.json" (
        builtins.toJSON {
          inherit component revision system;
          inherit (nativePackages.cli) version;
          artifacts = lib.mapAttrs (_: toString) spec.artifacts;
        }
      );
    in
    {
      inherit
        checks
        tests
        required
        promotionGates
        promotionOutputs
        ;
      # Named jobs keep compiled dependencies rooted when Hydra collects build inputs.
      inherit (spec) artifacts dependencies;
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
