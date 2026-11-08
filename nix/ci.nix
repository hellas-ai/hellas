{
  bufLintCommand,
  clippyArgs,
  cargoSelections,
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
  s = cargoSelections;

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
      # Native build scripts copy source permissions into OUT_DIR. Keep registry
      # builds and different read-only vendor snapshots in separate caches.
      export CARGO_TARGET_DIR="''${CARGO_TARGET_DIR:-target/check/${builtins.baseNameOf cargoDeps}}"
      export CARGO_NET_OFFLINE=${lib.boolToString offline}
      export SQLX_OFFLINE=true
      ${lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
        export RUST_TEST_THREADS=1
      ''}
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
      # Release builds export CC=clang through the shared clang stdenv.
      pkgs.clangStdenv.cc
    ]
    # Native build scripts run in this deliberately minimal wrapper too.
    # Catena's libffi-sys configure step needs the ordinary stdenv shell and
    # POSIX utilities even though the Rust compiler itself does not.
    ++ pkgs.stdenv.initialPath
    # On Darwin the clang driver runs dsymutil whenever one command compiles
    # and links with -g, as build-script probes do. LLVM ships it, not the
    # cc-wrapper.
    ++ lib.optional pkgs.stdenv.hostPlatform.isDarwin pkgs.llvmPackages.llvm
    ++ workspaceNativeBuildInputs;

  # CI-gating checks. These surface as `apps.<sys>.check-<name>` for local and
  # external matrix runners.
  baseChecks = {
    actions =
      mk "check-actions"
        ''
          actionlint -config-file /dev/null .github/workflows/*.yml
          shellcheck --shell=sh install.sh
        ''
        [
          pkgs.actionlint
          pkgs.shellcheck
        ];
    # The same tests as `checks.<system>.unit`, uninstrumented; coverage and
    # its floors are enforced only by that derivation.
    unit = mkCargo "check-unit" "cargo test --locked --workspace" (cargoEnv rustToolchain);
    # Tests wait on events and fail only on a documented hang guard, so they
    # run with libtest's default parallelism rather than one at a time.
    regressions = mkCargo "check-regressions" ''
      cargo test --locked ${s.workspace}
    '' (cargoEnv rustToolchain);
    # Resolve the entire locked graph with an empty Cargo home before compiling.
    # This catches source replacement regressions without runner credentials.
    cargo-sources =
      mkCargo "check-cargo-sources" "cargo metadata --locked --format-version 1 > /dev/null"
        [ rustToolchain ];
    fmt = mk "check-fmt" "cargo fmt --all -- --check" [ rustToolchain ];
    clippy = mkCargo "check-clippy" "cargo clippy ${clippyArgs}" (cargoEnv rustToolchain);
    # The default CLI includes client, gateway and daemon. Check the optional
    # execution, indexing, consensus and telemetry integrations separately.
    clippy-features = mkCargo "check-clippy-features" (builtins.concatStringsSep " && " (
      map (selection: "cargo clippy ${selection} --all-targets -- -D warnings") (
        [
          s.cli-only-integration
          s.cli-only-indexer
          s.cli-only-otel
        ]
        ++ lib.optionals isValidatorHost [ s.cli-only-validator ]
      )
    )) (cargoEnv rustToolchain);
    # Compile consumers without validator feature unification masking missing
    # module gates or imports used only by the indexer API.
    chain-features = mkCargo "check-chain-features" ''
      cargo clippy ${s.chain-client-core} --all-targets -- -D warnings
      cargo clippy ${s.chain-proof-verify} --all-targets -- -D warnings
      cargo clippy ${s.chain-full-node} --all-targets -- -D warnings
      cargo check ${s.chain-test-support} --lib
      cargo check ${s.sdk-all} --all-targets
    '' (cargoEnv rustToolchain);
    # Run command tests locally as well as in the release package builds.
    cli = mkCargo "check-cli" ''
      cargo test ${s.cli-integration}
      cargo build ${s.cli} --bin hellas
      HELLAS_CLI_TEST_BINARY="$(realpath "''${CARGO_TARGET_DIR:-target}/debug/hellas")"
      export HELLAS_CLI_TEST_BINARY
      cargo test ${s.sdk-integration} --test native_execution cli_settles_paid_channel_without_provider -- --ignored
      cargo test ${s.sdk-integration} --test native_execution cli_buys_a_paid_job_end_to_end -- --ignored
      # The paid/grant composition case re-executes a Catena compile worker,
      # whose process isolation is implemented only on Linux.
      ${lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
        cargo test ${s.sdk-integration} --test native_execution cli_paid_and_grant_two_provider_composition -- --ignored
      ''}
      cargo test ${s.cli-otel-integration} --test grant_http metrics_scrape_observes_gateway_and_serve_work
    '' (cargoEnv rustToolchain);
    cloud = mkCargo "check-cloud" ''
      cargo test ${s.cloud}
      cargo test ${s.cli}
      cargo build ${s.cli}
    '' (cargoEnv rustToolchain);
    # The kernel's whole suite, including `tests/itf.rs` — the Quint↔Rust
    # replay that the entire abstract-correspondence story rests on — and
    # the exact-error pins in `tests/channel/`. `--all-features` is load
    # bearing: `secp256k1`, `webauthn`, and `test-support` gate whole test
    # files, and a bare `cargo test -p hellas-kernel` compiles them away
    # to empty binaries.
    kernel = mkCargo "check-kernel" "cargo test ${s.kernel}" (cargoEnv rustToolchain);
    executor = mkCargo "check-executor" "cargo test ${s.executor}" (cargoEnv rustToolchain);
    # Money-only consumers keep node authority, attestation and compression out
    # of their production dependency graph. Grant-aware dev fixtures are separate.
    channel-dependencies = mkCargo "check-channel-dependencies" ''
      assert_money_graph() {
        dependencies="$(cargo tree --locked --edges normal,build --prefix none "$@")"
        if grep -Eq '^(hellas-authority|hellas-attestation|brotli|flate2) v' <<< "$dependencies"; then
          printf '%s\n' "$dependencies"
          echo "authority, attestation or compression reached a money-only consumer" >&2
          exit 1
        fi
      }
      assert_money_graph -p hellas-channel --no-default-features
      assert_money_graph -p hellas-client --no-default-features --features work
      assert_money_graph -p hellas-chain --no-default-features --features work-watcher
      # Chain work-watcher already gets zstd through consensus storage. Guard
      # the lightweight channel and client graphs against adding it here.
      for package in hellas-channel hellas-client; do
        features=()
        if [[ "$package" == hellas-client ]]; then features=(--features work); fi
        dependencies="$(cargo tree --locked --edges normal,build --prefix none -p "$package" --no-default-features "''${features[@]}")"
        if grep -Eq '^zstd v' <<< "$dependencies"; then
          echo "zstd reached a lightweight $package consumer" >&2
          exit 1
        fi
      done
    '' (cargoEnv rustToolchain ++ [ pkgs.gnugrep ]);
    # The keyhole: providers run generic compute and know no models. Provider
    # crates must not reach client model code, and the provider half of the
    # CLI and SDK must not name it. Client model code stays client-side.
    provider-dependencies = mkCargo "check-provider-dependencies" ''
      for package in hellas-executor hellas-authority hellas-providers hellas-rpc hellas-channel hellas-admission hellas-store hellas-chain hellas-kernel; do
        dependencies="$(cargo tree --locked --edges normal,build --prefix none -p "$package")"
        if grep -Eq '^(hellas-client|hellas-gateway|hellas-presentation|catena-models|tokenizers|hound|png|safetensors) v' <<< "$dependencies"; then
          printf '%s\n' "$dependencies"
          echo "client model code reached provider crate $package" >&2
          exit 1
        fi
      done
      provider_paths=(
        crates/cli/src/commands/serve
        crates/cli/src/compute.rs
        crates/cli/src/content_configuration.rs
        crates/sdk/src/provider
        crates/sdk/src/provider.rs
        crates/sdk/src/paid_provider
        crates/sdk/src/paid_provider.rs
        crates/sdk/src/grant_provider.rs
      )
      existing=()
      for path in "''${provider_paths[@]}"; do
        if [[ -e "$path" ]]; then existing+=("$path"); fi
      done
      if grep -rnE 'hellas_client::model|ModelPackage|ModelRequest|catena_models' "''${existing[@]}"; then
        echo "provider code names client model code" >&2
        exit 1
      fi
    '' (cargoEnv rustToolchain ++ [ pkgs.gnugrep ]);
    # RPC owns the generated Work/WorkSetup interfaces and their wire-id pins;
    # Channel and authority own the canonical records and durable orchestration.
    # Test each complete package so service/method identity pins stay covered.
    rpc-work =
      mkCargo "check-rpc-work"
        "cargo check ${s.rpc} && cargo test ${s.rpc-work} && cargo test ${s.channel-authority} && cargo clippy ${s.rpc-work} --all-targets -- -D warnings && cargo clippy ${s.channel-authority} --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    # The client's paid-work half and the oracle inside it. `work` is off
    # by default on `hellas-client`, so `check-clippy` compiles none of
    # it: not the orchestrator, not its end-to-end test, and not the
    # oracle's own suite — the one that says what a failed independent
    # check does. All three run only here.
    client-work =
      mkCargo "check-client-work"
        "cargo test ${s.client-work} && cargo clippy ${s.client-work} --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    # HTTP boundaries and the bounded file primitives shared by hosts.
    http-fetch = mkCargo "check-http-fetch" "cargo test ${s.http}" (cargoEnv rustToolchain);
    # Native host composition has one implementation for both funding modes.
    sdk-paid-work = mkCargo "check-sdk-paid-work" ''
      # These native cases each start a six-validator devnet. Serializing the
      # test harness avoids cross-test resource starvation; the cases retain
      # their own concurrent-client and cancellation assertions.
      RUST_TEST_THREADS=1 cargo test ${s.sdk-integration}
      cargo clippy ${s.sdk-integration} --all-targets -- -D warnings
    '' (cargoEnv rustToolchain);
    # The chain service's wire-id pins compile only under `chain`, which
    # `work` does not pull in. `check-validator` links hellas-rpc with
    # that feature but runs hellas-chain's tests, not hellas-rpc's, so
    # until this line existed the light-client service and method ids
    # were pinned by a test no gate ran. A rotated chain id would have
    # reached deployed nodes with every check green.
    rpc-chain =
      mkCargo "check-rpc-chain"
        "cargo test ${s.rpc-chain} && cargo clippy ${s.rpc-chain} --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    validator = mkCargo "check-validator" "cargo test ${s.chain-validator-integration}" (
      cargoEnv rustToolchain
    );
    # `check-validator` above runs tests, where `dead_code` is only a
    # warning, so the two feature sets a node actually ships in were the
    # only ones never linted. Three items in `execution::owner_tree` and
    # four test-support helpers sat dead in them until 2026-09-22, and the
    # same shape had already shipped once as a broken `cfg` on
    # `kernel::execute_all`. Lint both.
    chain-validator-lint =
      mkCargo "check-chain-validator-lint"
        "cargo clippy ${s.chain-validator} --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    chain-indexer-lint =
      mkCargo "check-chain-indexer-lint"
        "cargo clippy ${s.chain-indexer} --all-targets -- -D warnings && cargo clippy ${s.chain-indexer-api} --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    # The finalized-block codec without a database or a mempool: the
    # feature an endpoint enables to read the block its channel opened
    # in. Every other gate reaches this code through `indexer`, which
    # also enables the execution layer the split was made to avoid — so
    # only this line fails if the codec grows a dependency back on it.
    chain-block-view =
      mkCargo "check-chain-block-view" "cargo clippy ${s.chain-block-view} --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    # The settlement watcher's block source: the codec above plus the
    # paid endpoint's journal. It is the only dimension that compiles
    # `hellas-chain` and `hellas-channel` together, so it is the only
    # one that fails when the two disagree about what a finalized block
    # hands a watcher.
    chain-work-watcher =
      mkCargo "check-chain-work-watcher"
        "cargo clippy ${s.chain-work-watcher} --all-targets -- -D warnings"
        (cargoEnv rustToolchain);
    # The setup driver end to end. It needs both halves at once —
    # `validator` for the database, the kernel, and the indexer, and
    # `work-watcher` for the journal and the driver — and neither of the
    # two dimensions above runs a test with the other's code compiled
    # in. This is the only line that runs a paid channel being opened
    # against real finalized blocks.
    chain-setup = mkCargo "check-chain-setup" "cargo test ${s.chain-setup}" (cargoEnv rustToolchain);
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
    wasm-rpc =
      mkCargo "check-wasm-rpc"
        "cargo check -p hellas-rpc --no-default-features --target wasm32-unknown-unknown"
        (cargoEnv (rustToolchain.override { targets = [ "wasm32-unknown-unknown" ]; }));
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
          "regressions"
          "chain-setup"
          # Same reason as `validator` above: validators are deployed on x86
          # only, so the feature set is not built on other hosts. Linting it
          # there would widen what non-x86 runners compile without widening
          # what they ship.
          "chain-validator-lint"
        ]
    )
    // extraChecks;

  lintNames = [
    "actions"
    "cargo-sources"
    "fmt"
    "clippy"
    "sort"
    "taplo"
    "buf"
    "deny"
    "deadnix"
    "statix"
    "nixfmt"
    "channel-dependencies"
    "provider-dependencies"
    "xet-no-alloc"
  ];
  lintChecks = lib.filterAttrs (name: _: builtins.elem name lintNames) checks;
  mergeChecks =
    lintChecks
    // {
      inherit (checks) unit;
    }
    // lib.optionalAttrs isValidatorHost { inherit (checks) regressions; };

  # Auto-fix variants. Not all checks have one (e.g. test, wasm-rpc).
  fixes = {
    fmt = mk "fix-fmt" "cargo fmt --all" [ rustToolchain ];
    clippy =
      mkCargo "fix-clippy" "cargo clippy ${s.workspace} --all-targets --fix --allow-dirty --allow-staged"
        (cargoEnv rustToolchain);
    sort = mk "fix-sort" "cargo-sort --workspace --no-format" [ pkgs.cargo-sort ];
  };

  # Merge checks and release checks share the same individual commands.
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
    portable-x86_64 = "cross-x86_64-linux-musl-cli";
    portable-aarch64 = "cross-aarch64-linux-musl-cli";
    hellas-rpc-wasm = "hellas-rpc-wasm";
  }
  // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
    docker = "docker";
  }
  # CUDA/HIP images run in the dedicated trusted-branch image job, which
  # streams archives for publishing without requiring a Docker daemon.
  // lib.optionalAttrs isValidatorHost {
    cli-validator = "cli-validator";
  };
in
{
  inherit
    checks
    fixes
    mergeChecks
    ;
  builds = ciBuilds;
  checkAll = mkAggregate "check-all" (lib.attrValues mergeChecks);
  checkLints = mkAggregate "check-lints" (lib.attrValues lintChecks);
  checkRelease = mkAggregate "check-release" (lib.attrValues checks);
  fixAll = mkAggregate "fix-all" (lib.attrValues fixes);
}
