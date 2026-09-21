{
  bufLintCommand,
  denyCommand,
  cargoDeps,
  pkgs,
  lib,
  rustToolchain,
  workspaceNativeBuildInputs,
  extraChecks ? { },
}:
let
  isValidatorHost = pkgs.stdenv.hostPlatform.system == "x86_64-linux";

  mk =
    name: cmd: inputs:
    pkgs.writeShellApplication {
      inherit name;
      text = ''
        export PATH="${lib.makeBinPath inputs}"
        ${cmd}
      '';
    };

  # Use the same fixed-output sources as release builds. In particular, Cargo
  # must not try SSH credentials for a private git dependency during linting.
  cargoConfig = pkgs.runCommand "hellas-ci-cargo-config" { } ''
    substitute ${cargoDeps}/.cargo/config.toml "$out" \
      --replace-fail 'directory = "cargo-vendor-dir"' 'directory = "${cargoDeps}"'
  '';

  # The audit needs registry index records to check crate yanks. Retain normal
  # crates.io fetching there, while git dependencies still come from Nix.
  cargoAuditConfig = pkgs.runCommand "hellas-ci-cargo-audit-config" { } ''
    substitute ${cargoConfig} "$out" --replace-fail '[source.crates-io]
    replace-with = "vendored-sources"' ""
  '';

  mkCargoConfigured =
    config: offline: name: cmd: inputs:
    mk name ''
      cargo_home=$(mktemp -d)
      trap 'rm -rf "$cargo_home"' EXIT
      cp ${config} "$cargo_home/config.toml"
      export CARGO_HOME="$cargo_home"
      export CARGO_NET_OFFLINE=${lib.boolToString offline}
      ${cmd}
    '' ([ pkgs.coreutils ] ++ inputs);

  mkCargo = mkCargoConfigured cargoConfig true;

  cargoEnv =
    toolchain:
    [
      toolchain
      # Unix FIFO-adversary regressions create their fixtures with `mkfifo`.
      # Keep that test dependency explicit: writeShellApplication otherwise
      # gives Cargo a deliberately minimal PATH.
      pkgs.coreutils
      pkgs.stdenv.cc
    ]
    # Native build scripts run in this deliberately minimal wrapper too.
    # Catena's libffi-sys configure step needs the ordinary stdenv shell and
    # POSIX utilities even though the Rust compiler itself does not.
    ++ pkgs.stdenv.initialPath
    ++ workspaceNativeBuildInputs;

  # CI-gating checks. These surface as `apps.<sys>.check-<name>` for local and
  # external matrix runners.
  baseChecks = {
    # Resolve the entire locked graph with an empty Cargo home before compiling.
    # This catches source replacement regressions without runner credentials.
    cargo-sources =
      mkCargo "check-cargo-sources" "cargo metadata --locked --format-version 1 > /dev/null"
        [ rustToolchain ];
    fmt = mk "check-fmt" "cargo fmt --all -- --check" [ rustToolchain ];
    clippy = mkCargo "check-clippy" "cargo clippy --workspace --all-targets -- -D warnings" (
      cargoEnv rustToolchain
    );
    # Default features alone leave most of the CLI unlinted: `evaluate`,
    # `node` and `gateway` are all off by default, which is most of what
    # the binary actually does. So the buildable feature sets are named and
    # checked independently.
    clippy-features = mkCargo "check-clippy-features" (builtins.concatStringsSep " && " (
      map
        (f: "cargo clippy -p hellas-cli --no-default-features --features ${f} --all-targets -- -D warnings")
        (
          [
            "chain"
            "indexer"
            "evaluate"
            "node"
            "llm"
            "gateway"
            "otel"
          ]
          ++ lib.optionals isValidatorHost [ "validator" ]
        )
    )) (cargoEnv rustToolchain);
    # The kernel's whole suite, including `tests/itf.rs` — the Quint↔Rust
    # replay that the entire abstract-correspondence story rests on — and
    # the exact-error pins in `tests/channel/`. `--all-features` is load
    # bearing: `secp256k1`, `webauthn`, and `test-support` gate whole test
    # files, and a bare `cargo test -p hellas-kernel` compiles them away
    # to empty binaries.
    kernel = mkCargo "check-kernel" "cargo test -p hellas-kernel --all-features" (
      cargoEnv rustToolchain
    );
    executor = mkCargo "check-executor" "cargo test -p hellas-executor" (cargoEnv rustToolchain);
    # The paid-work wire records stay behind RPC's `work` feature, while
    # endpoint workflow and durable recovery live in `hellas-work`.
    # Neither enters the default graph, so both need an explicit gate.
    #
    # The whole package runs, not one named test file: `work` pulls
    # `evaluate` and therefore `execute`, so this line is also what
    # compiles `pb::id_pins` — the wire-id pins that no other gate here
    # reaches, the `hellas.work.v1` service and method among them.
    # Naming a single `--test` target would leave a rotated service id
    # unnoticed, which is exactly what happened once.
    rpc-work =
      mkCargo "check-rpc-work"
        "cargo test -p hellas-rpc --features work && cargo test -p hellas-work && cargo clippy -p hellas-rpc --features work --all-targets -- -D warnings && cargo clippy -p hellas-work --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    # The client's paid-work half and the oracle inside it. `work` is off
    # by default on `hellas-client`, so `check-clippy` compiles none of
    # it: not the orchestrator, not its end-to-end test, and not the
    # oracle's own suite — the one that says what a failed independent
    # check does. All three run only here.
    client-work =
      mkCargo "check-client-work"
        "cargo test -p hellas-client --features work && cargo clippy -p hellas-client --features work --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    # The chain service's wire-id pins compile only under `chain`, which
    # `work` does not pull in. `check-validator` links hellas-rpc with
    # that feature but runs hellas-chain's tests, not hellas-rpc's, so
    # until this line existed the light-client service and method ids
    # were pinned by a test no gate ran. A rotated chain id would have
    # reached deployed nodes with every check green.
    rpc-chain =
      mkCargo "check-rpc-chain"
        "cargo test -p hellas-rpc --features chain && cargo clippy -p hellas-rpc --features chain --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    validator =
      mkCargo "check-validator" "cargo test -p hellas-chain --no-default-features --features validator"
        (cargoEnv rustToolchain);
    # `check-validator` above runs tests, where `dead_code` is only a
    # warning, so the two feature sets a node actually ships in were the
    # only ones never linted. Three items in `execution::owner_tree` and
    # four test-support helpers sat dead in them until 2026-09-22, and the
    # same shape had already shipped once as a broken `cfg` on
    # `kernel::execute_all`. Lint both.
    chain-validator-lint =
      mkCargo "check-chain-validator-lint"
        "cargo clippy -p hellas-chain --no-default-features --features validator --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    chain-indexer-lint =
      mkCargo "check-chain-indexer-lint"
        "cargo clippy -p hellas-chain --no-default-features --features indexer --all-targets -- -D warnings && cargo clippy -p hellas-chain --no-default-features --features indexer-api --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    # The finalized-block codec without a database or a mempool: the
    # feature an endpoint enables to read the block its channel opened
    # in. Every other gate reaches this code through `indexer`, which
    # also enables the execution layer the split was made to avoid — so
    # only this line fails if the codec grows a dependency back on it.
    chain-block-view =
      mkCargo "check-chain-block-view"
        "cargo clippy -p hellas-chain --no-default-features --features block-view --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    # The settlement watcher's block source: the codec above plus the
    # paid endpoint's journal. It is the only dimension that compiles
    # `hellas-chain` and `hellas-work` together, so it is the only
    # one that fails when the two disagree about what a finalized block
    # hands a watcher.
    chain-work-watcher =
      mkCargo "check-chain-work-watcher"
        "cargo clippy -p hellas-chain --no-default-features --features work-watcher --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    # The setup driver end to end. It needs both halves at once —
    # `validator` for the database, the kernel, and the indexer, and
    # `work-watcher` for the journal and the driver — and neither of the
    # two dimensions above runs a test with the other's code compiled
    # in. This is the only line that runs a paid channel being opened
    # against real finalized blocks.
    chain-setup =
      mkCargo "check-chain-setup"
        "cargo test -p hellas-chain --no-default-features --features validator,work-watcher"
        (cargoEnv rustToolchain);
    sort = mk "check-sort" "cargo-sort --workspace --check --no-format" [ pkgs.cargo-sort ];
    taplo =
      mk "check-taplo" "taplo fmt --option 'indent_string=    ' --check '*.toml' 'crates/**/Cargo.toml'"
        [
          pkgs.taplo
        ];
    buf = mk "check-buf" bufLintCommand [ pkgs.buf ];
    deny = mkCargoConfigured cargoAuditConfig false "check-deny" denyCommand (
      (cargoEnv rustToolchain)
      ++ [
        pkgs.cargo-deny
        pkgs.git
      ]
    );
    deadnix = mk "check-deadnix" ''
      shopt -s globstar
      deadnix --fail flake.nix nix/**/*.nix
    '' [ pkgs.deadnix ];
    statix = mk "check-statix" "statix check ." [ pkgs.statix ];
    nixfmt = mk "check-nixfmt" ''
      shopt -s globstar
      nixfmt --check flake.nix nix/**/*.nix
    '' [ pkgs.nixfmt ];
    flake-check = mk "check-flake-check" "nix flake check --accept-flake-config --no-build" [
      pkgs.nix
    ];
    wasm-rpc = mkCargo "check-wasm-rpc" "cargo check -p hellas-rpc --target wasm32-unknown-unknown" (
      cargoEnv (rustToolchain.override { targets = [ "wasm32-unknown-unknown" ]; })
    );
    wasm-chain = mkCargo "check-wasm-chain" ''
      export CC_wasm32_unknown_unknown=${lib.getExe' pkgs.llvmPackages.clang-unwrapped "clang"}
      export AR_wasm32_unknown_unknown=${lib.getExe' pkgs.llvmPackages.llvm "llvm-ar"}
      cargo check -p hellas-chain --no-default-features --features wasm-client --target wasm32-unknown-unknown
    '' (cargoEnv (rustToolchain.override { targets = [ "wasm32-unknown-unknown" ]; }));
    wasm-xet = mkCargo "check-wasm-xet" "cargo check -p hellas-xet --target wasm32-unknown-unknown" (
      cargoEnv (rustToolchain.override { targets = [ "wasm32-unknown-unknown" ]; })
    );
    # `hellas-xet` sits inside the `#![no_std]` kernel's dependency
    # closure, which must be allocation-free. With default features off
    # the crate takes the `alloc` name for an empty module of its own, so
    # this build is what fails — loudly, at compile time — the moment
    # someone reaches for a `Vec` there again. It cannot ride along with
    # `check-clippy`: a workspace build unifies `chunking` back on.
    xet-no-alloc = mkCargo "check-xet-no-alloc" "cargo build -p hellas-xet --no-default-features" (
      cargoEnv rustToolchain
    );
  };

  checks =
    (
      if isValidatorHost then
        baseChecks
      else
        builtins.removeAttrs baseChecks [
          "validator"
          "chain-setup"
        ]
    )
    // extraChecks;

  # Auto-fix variants. Not all checks have one (e.g. test, wasm-rpc).
  fixes = {
    fmt = mk "fix-fmt" "cargo fmt --all" [ rustToolchain ];
    clippy =
      mkCargo "fix-clippy" "cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged"
        (cargoEnv rustToolchain);
    sort = mk "fix-sort" "cargo-sort --workspace --no-format" [ pkgs.cargo-sort ];
  };

  # `nix run .#check` runs every gating check.
  # `nix run .#fix`   runs the auto-fix variants.
  mkAggregate =
    name: pkgList:
    pkgs.writeShellApplication {
      inherit name;
      text = lib.concatMapStringsSep "\n" lib.getExe pkgList;
    };

  # Extended builds. Each value is an attribute path under `packages.<system>`
  # consumed by matrix runners as
  # `nix build .#packages.<system>.<attr>`.
  ciBuilds = {
    cli = "cli";
    static-x86_64 = "cross-x86_64-linux-musl-cli";
    static-aarch64 = "cross-aarch64-linux-musl-cli";
    hellas-rpc-wasm = "hellas-rpc-wasm";
  }
  // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
    docker = "docker";
  }
  # CUDA and HIP images are intentionally omitted from the hosted matrix.
  # Build them on the self-hosted release runner once it is registered again.
  // lib.optionalAttrs isValidatorHost {
    cli-validator = "cli-validator";
    cli-catena = "cli-catena";
  };
in
{
  inherit checks fixes;
  builds = ciBuilds;
  checkAll = mkAggregate "check-all" (lib.attrValues checks);
  fixAll = mkAggregate "fix-all" (lib.attrValues fixes);
}
