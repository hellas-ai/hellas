{
  pkgs,
  lib,
  rustToolchain,
  cargoToolPackages,
  commonToolPackages,
}:
let
  modelTestModules = [
    "l1.qnt"
    "l1_fees.qnt"
  ];

  runSpecs = [
    {
      model = "l1.qnt";
      maxSamples = 500;
      maxSteps = 8;
      invariants = [
        "valueConserved"
        "atMostOneLiveEdge"
        "noNegativeValue"
        "liveEdgesAreKnown"
        "liveCoinsAreKnown"
        "wiringIsExpected"
        "liveCoinsHaveCanonicalValue"
        "payoutsHonorBindings"
        "payoutOutputsPaired"
        "deadSlotsAreZero"
        "liveEdgesHaveCanonicalValue"
        "fundingInputsConsumed"
        "heightAtLeastGenesis"
        "fundingAuthorized"
      ];
    }
    {
      model = "l1_fees.qnt";
      maxSamples = 500;
      maxSteps = 8;
      invariants = [
        "valueAccounted"
        "partyValueAccounted"
        "constantsBalanced"
        "noNegativeBucket"
        "reserveAtLeastCommittedFee"
        "paidIsLifecycleAmount"
        "currentCloseFeeKnown"
        "heightAtLeastGenesis"
        "atMostOneLiveEdge"
        "liveCoinsAreKnown"
        "liveEdgesAreKnown"
        "deadSlotsAreZero"
        "liveEdgesCarryPrincipalAndReserve"
        "reserveLivesWithEdge"
        "closeFeeLivesWithEdge"
        "termsCoherentForClose"
        "escapeHatchBoundsNonNegative"
        "escapeHatchTotalMatchesRecoverableValue"
        "fundingShapeDecisionsCoherent"
        "fundingAuthorized"
        "expiredLiveHasTimeoutPath"
        "nonTimeoutProofsExpire"
      ];
    }
  ];

  verifySpecs = [
    {
      model = "l1.qnt";
      maxSteps = 5;
      invariants = [
        "valueConserved"
        "noNegativeValue"
        "atMostOneLiveEdge"
        "liveCoinsAreKnown"
        "liveEdgesAreKnown"
        "wiringIsExpected"
        "liveCoinsHaveCanonicalValue"
        "payoutsHonorBindings"
        "payoutOutputsPaired"
        "deadSlotsAreZero"
        "liveEdgesHaveCanonicalValue"
        "fundingInputsConsumed"
        "heightAtLeastGenesis"
        "fundingAuthorized"
      ];
    }
    {
      model = "l1_fees.qnt";
      maxSteps = 4;
      invariants = [
        "valueAccounted"
        "partyValueAccounted"
        "constantsBalanced"
        "noNegativeBucket"
        "reserveAtLeastCommittedFee"
        "paidIsLifecycleAmount"
        "currentCloseFeeKnown"
        "heightAtLeastGenesis"
        "atMostOneLiveEdge"
        "liveCoinsAreKnown"
        "liveEdgesAreKnown"
        "deadSlotsAreZero"
        "liveEdgesCarryPrincipalAndReserve"
        "reserveLivesWithEdge"
        "closeFeeLivesWithEdge"
        "termsCoherentForClose"
        "escapeHatchBoundsNonNegative"
        "escapeHatchTotalMatchesRecoverableValue"
        "fundingShapeDecisionsCoherent"
        "fundingAuthorized"
        "expiredLiveHasTimeoutPath"
        "nonTimeoutProofsExpire"
      ];
    }
  ];

  modelPath = model: "models/${model}";
  invariantFlags = invariants: lib.concatMapStringsSep " " (name: "--invariants=${name}") invariants;
  invariantArgs = invariants: lib.concatStringsSep " " invariants;

  testCommand = lib.concatMapStringsSep "\n" (model: ''
    quint typecheck ${modelPath model}
    quint test ${modelPath model} --verbosity=2
  '') modelTestModules;

  simulationCommand = lib.concatMapStringsSep "\n" (spec: ''
    quint run ${modelPath spec.model} --max-samples=${toString spec.maxSamples} --max-steps=${toString spec.maxSteps} ${invariantFlags spec.invariants} --verbosity=1
  '') runSpecs;

  verificationCommand = lib.concatMapStringsSep "\n" (spec: ''
    quint verify ${modelPath spec.model} ${
      lib.optionalString (spec ? maxSteps) "--max-steps=${toString spec.maxSteps}"
    } --invariants ${invariantArgs spec.invariants} --verbosity=1
  '') verifySpecs;

  fixtureCommand = ''
    rm -f models/traces/*.itf.json
    mkdir -p models/traces
    quint test models/l1.qnt --out-itf 'models/traces/l1_{test}.itf.json' --verbosity=0
    quint test models/l1_fees.qnt --out-itf 'models/traces/l1_fees_{test}.itf.json' --verbosity=0
  '';

  modelRuntimePackages = with pkgs; [
    quint
    temurin-bin
    stdenv.cc.cc.lib
  ];

  devShellPackages = [
    rustToolchain
    pkgs.rust-analyzer
    pkgs.llvmPackages.lld
    pkgs.pkg-config
    pkgs.git
  ]
  ++ modelRuntimePackages
  ++ cargoToolPackages
  ++ commonToolPackages;

  mkModelApp =
    {
      name,
      command,
      needsJvm ? false,
    }:
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = [
        pkgs.coreutils
        pkgs.diffutils
        pkgs.git
        pkgs.jq
        pkgs.quint
      ]
      ++ lib.optionals needsJvm [ pkgs.temurin-bin ];
      text = ''
        repo_root="$(git rev-parse --show-toplevel)"
        cd "$repo_root/crates/kernel"
        ${lib.optionalString needsJvm ''
          export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib''${LD_LIBRARY_PATH:+:''${LD_LIBRARY_PATH}}"
        ''}
        ${command}
      '';
    };

  modelTest = mkModelApp {
    name = "hellas-kernel-model-test";
    command = testCommand;
  };

  modelRun = mkModelApp {
    name = "hellas-kernel-model-run";
    command = simulationCommand;
  };

  modelVerifyLocal = mkModelApp {
    name = "hellas-kernel-model-verify";
    command = verificationCommand;
    needsJvm = true;
  };

  # Quint reuses an Apalache server on localhost:8822 and terminates a server
  # it started when it exits. Concurrent Linux CI jobs must therefore verify
  # in separate Nix build sandboxes, each with its own loopback and processes.
  # Track all Quint imports, but do not invalidate verification for docs/traces.
  modelSource = lib.fileset.toSource {
    root = ../crates/kernel;
    fileset = lib.fileset.fileFilter (file: file.hasExt "qnt") ../crates/kernel/models;
  };

  modelVerifyResult =
    pkgs.runCommand "hellas-kernel-model-verification"
      {
        src = modelSource;
        nativeBuildInputs = modelRuntimePackages;
      }
      ''
        set -o pipefail
        cp -r "$src/models" ./models
        chmod -R u+w ./models
        export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib''${LD_LIBRARY_PATH:+:''${LD_LIBRARY_PATH}}"
        mkdir -p "$out"
        {
          ${verificationCommand}
        } 2>&1 | tee "$out/verification.log"
        touch "$out/passed"
      '';

  # Referencing the result forces the actual verification build, rather than
  # merely building an executable that would still share the runner's port.
  # Darwin has no private network namespace: retain its existing local command
  # and make no claim that simultaneous Darwin invocations are isolated.
  modelVerify =
    if pkgs.stdenv.hostPlatform.isLinux then
      pkgs.writeShellApplication {
        name = "hellas-kernel-model-verify";
        runtimeInputs = [ pkgs.coreutils ];
        text = ''
          cat ${modelVerifyResult}/verification.log
        '';
      }
    else
      modelVerifyLocal;

  # Committed ITF traces are what the Rust replays read. If a model
  # changes and the traces are not regenerated, the replay keeps
  # asserting the OLD abstract behaviour and CI stays green — the
  # correspondence silently becomes fiction. This regenerates into a
  # scratch tree and fails on any drift.
  #
  # Compares semantic content only: quint stamps a wall-clock time into
  # `#meta`, so a byte-wise diff could never pass.
  freshnessCommand = crate: models: ''
    repo_root="$(git rev-parse --show-toplevel)"
    scratch="$(mktemp -d)"
    trap 'rm -rf "$scratch"' EXIT
    committed="$repo_root/crates/${crate}/models/traces"
    regenerated="$scratch/traces"
    mkdir -p "$regenerated"
    canon() {
      for f in "$1"/*.itf.json; do
        printf '== %s\n' "$(basename "$f")"
        jq -S 'del(."#meta")' "$f"
      done
    }
    canon "$committed" > "$scratch/committed.txt"
    ${lib.concatMapStringsSep "\n" (m: ''
      quint test models/${m}.qnt --out-itf "$regenerated/${m}_{test}.itf.json" --verbosity=0
    '') models}
    canon "$regenerated" > "$scratch/regenerated.txt"
    if ! diff -u "$scratch/committed.txt" "$scratch/regenerated.txt"; then
      echo "ITF traces are stale: regenerate with 'nix run .#update-${crate}-model-fixtures'" >&2
      exit 1
    fi
  '';

  kernelFixtureFreshness = mkModelApp {
    name = "hellas-kernel-fixture-freshness";
    command = freshnessCommand "kernel" [
      "l1"
      "l1_fees"
    ];
  };

  modelFixtures = mkModelApp {
    name = "hellas-kernel-model-fixtures";
    command = fixtureCommand;
  };
in
{
  buildChecks = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
    kernel-model-verify = modelVerifyResult;
  };

  devShell = pkgs.mkShell {
    packages = devShellPackages;
    RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
    LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
  };

  checks = {
    kernel-models = modelTest;
    kernel-model-run = modelRun;
    kernel-model-verify = modelVerify;
    kernel-fixture-freshness = kernelFixtureFreshness;
  };

  apps = {
    "check-kernel-models" = {
      type = "app";
      program = lib.getExe modelTest;
      meta.description = "Run hellas-kernel Quint model tests";
    };
    "check-kernel-model-run" = {
      type = "app";
      program = lib.getExe modelRun;
      meta.description = "Run hellas-kernel Quint model simulations";
    };
    "check-kernel-model-verify" = {
      type = "app";
      program = lib.getExe modelVerify;
      meta.description = "Run hellas-kernel Quint model verification";
    };
    "update-kernel-model-fixtures" = {
      type = "app";
      program = lib.getExe modelFixtures;
      meta.description = "Regenerate hellas-kernel Quint ITF fixtures";
    };
  };
}
