{
  self,
  system,
  nixpkgs,
  rust-overlay,
  # When set, builds everything for this target triple via `pkgsCross`.
  # Leave null for native builds.
  crossSystem ? null,
}:
let
  overlays = [
    (import rust-overlay)
    (final: _prev: {
      hellasLib = import ./lib { pkgs = final; };
    })
  ];
  pkgs = import nixpkgs (
    {
      inherit system overlays;
      config.allowUnfree = true;
    }
    // nixpkgs.lib.optionalAttrs (crossSystem != null) { inherit crossSystem; }
  );
  inherit (pkgs) lib;

  isCross = crossSystem != null;
  targetTriple = pkgs.stdenv.hostPlatform.rust.rustcTarget;

  rustToolchain = (self.lib.rustToolchain pkgs.buildPackages).override {
    targets = lib.optional isCross targetTriple;
  };

  # clangStdenv avoids the GCC 15 ICE in zstd-sys (gimple_lower_bitint crash).
  # Under pkgsCross this is the *target* stdenv.
  stdenv = pkgs.clangStdenv;

  rustPlatform = pkgs.makeRustPlatform {
    rustc = rustToolchain;
    cargo = rustToolchain;
    inherit stdenv;
  };

  # Only what Cargo builds and tests read, so other edits (Nix, CI, most docs)
  # leave the Rust derivations unchanged. A missing file fails loudly: tests
  # read these with include_str!/include_bytes! or from CARGO_MANIFEST_DIR.
  buildSrc = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../.cargo/config.toml
      ../Cargo.toml
      ../Cargo.lock
      ../clippy.toml
      ../crates
      ../proto
      # Documentation that tests check against the implementation.
      ../docs/admin.md
      ../docs/examples/faucet-provider.json
      ../docs/http-gateway.md
      ../docs/jobs.md
      ../docs/machine-provider.json
      ../docs/paid-gateway.md
    ];
  };

  workspaceBuildInputs = [ ];
  workspaceNativeBuildInputs = with pkgs.buildPackages; [
    pkg-config
    protobuf
    llvmPackages.lld
  ];

  rev = self.rev or self.dirtyRev or "unknown";

  rustEnvTarget = pkgs.stdenv.hostPlatform.rust.cargoEnvVarTarget;

  crossEnv = lib.optionalAttrs isCross {
    CARGO_BUILD_TARGET = targetTriple;
    "CARGO_TARGET_${rustEnvTarget}_LINKER" = "${stdenv.cc}/bin/${stdenv.cc.targetPrefix}cc";
    # libffi-sys (via catena-lang) builds libffi with autoconf, whose link test
    # fails on the static clang toolchain's missing libgcc_eh. Rust links its own unwinder.
    "CFLAGS_${lib.replaceStrings [ "-" ] [ "_" ] targetTriple}" = "--unwindlib=none";
  };

  commonArgs = {
    pname = "hellas";
    version = "0.1.0";
    src = buildSrc;
    cargoLock = {
      lockFile = ../Cargo.lock;
      outputHashes = {
        "catena-lang-0.1.0" = "sha256-U3aYYin89Q0uIcUVB3gwGsGTC3/N+F32qorECfo+kHs=";
        "catena-models-0.1.0" = "sha256-MhmPrLGvVb0be72X3+Dv1tZXWfL24ckXyojB7me+KUk=";
        "commonware-actor-2026.7.0" = "sha256-Z1mtElU3fYKzHW0BTALtb6Bm3xasEJuH/dKlZXEDt+8=";
      };
    };
    inherit stdenv;
    auditable = false;
    # sqlx's query macros check against the committed `.sqlx` metadata, so a
    # build never needs a live database.
    SQLX_OFFLINE = "true";
    SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
    NIX_SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
    buildInputs = workspaceBuildInputs;
    nativeBuildInputs = workspaceNativeBuildInputs;
    # Exercise real UDP bootstrap wherever this builder can execute the musl
    # target; CLI parser and HTTP provider tests cannot detect a musl UDP
    # receive regression such as noq-udp misreading cmsg payload alignment.
    postBuild =
      lib.optionalString
        (pkgs.stdenv.hostPlatform.isMusl && pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform)
        ''
          bootstrapTest=node_control::bootstrap::tests::pairing_commits_the_saved_credential_and_cannot_be_replayed
          cargo test --offline --release --target ${targetTriple} \
            -p hellas-sdk --features hellas-chain/validator "$bootstrapTest" \
            --no-run --message-format=json-render-diagnostics > bootstrap-test-build.json
          bootstrapTestBinary=$(${pkgs.buildPackages.jq}/bin/jq -sre '
            [.[] | select(.reason == "compiler-artifact" and .profile.test == true
              and .target.name == "hellas_sdk" and .target.kind == ["lib"]
              and .executable != null) | .executable]
            | if length == 1 then .[0] else error("expected one SDK test executable") end
          ' bootstrap-test-build.json)
          # Bound test execution only; invoking Cargo again can trigger rebuilds.
          timeout 120 "$bootstrapTestBinary" "$bootstrapTest" --exact
          startupTest=node_control::bootstrap::tests::provider_runtime_dials_tls_relay_with_default_stack
          "$bootstrapTestBinary" "$startupTest" --exact
        '';
    checkInputs = with pkgs; [ cargo-outdated ];
    separateDebugInfo = true;
    # stdenv's default stripDebugList only does --strip-debug on bin/;
    # stripAllList promotes it to --strip-all so .symtab goes too.
    stripAllList = [ "bin" ];
    meta.mainProgram = "hellas";
  }
  // crossEnv;

  mkHellasPackage = overrides: rustPlatform.buildRustPackage (commonArgs // overrides);

  # Crane builds the workspace's external dependencies once (`cargoDeps`) and
  # hands the compiled target directory to each check, which then compiles
  # only Hellas crates. Hydra populates cache.hellas.ai with these outputs.
  craneLib = ((self.inputs.crane.mkLib pkgs).overrideToolchain (_: rustToolchain)).overrideScope (
    _: _: { stdenvSelector = p: p.clangStdenv; }
  );

  # Feature set that clippy and the regression suite build with.
  integrationFeatures = "integration-tests,hellas-chain/indexer-api,hellas-cli/compute";
  # Shared with the `check-clippy` app in ci.nix.
  clippyArgs = "--workspace --all-targets --features ${integrationFeatures} -- -D warnings -W clippy::large_futures -W clippy::large_stack_frames";

  # Every package and feature selection a release validation compiles, as
  # Cargo arguments. The ci.nix checks run their tests and lints under these;
  # `cargoDeps` compiles each one's dependencies, and `feature-targets`
  # type-checks every target of each, so a pull request compiles what Hydra
  # later tests. Validators ship on x86_64 Linux only, so the validator
  # selections exist only there.
  cargoSelections =
    let
      chain = features: "-p hellas-chain --no-default-features --features ${features}";
      cliOnly = features: "-p hellas-cli --no-default-features --features ${features}";
    in
    {
      workspace = "--workspace --features ${integrationFeatures}";
      cli = "-p hellas-cli";
      cli-compute = "-p hellas-cli --features compute";
      # Command tests serve and run Compute through the CLI binary.
      cli-integration = "-p hellas-cli --features compute,integration-tests";
      cli-otel-integration = "-p hellas-cli --features compute,otel,integration-tests";
      cli-only-integration = cliOnly "integration-tests";
      cli-only-indexer = cliOnly "indexer";
      cli-only-otel = cliOnly "otel";
      cloud = "-p hellas-cloud";
      client-work = "-p hellas-client --features work";
      http = "-p hellas-gateway -p hellas-providers -p hellas-private -p hellas-store";
      rpc = "-p hellas-rpc --no-default-features";
      rpc-work = "-p hellas-rpc --features work";
      rpc-chain = "-p hellas-rpc --features chain";
      channel-authority = "-p hellas-channel -p hellas-authority";
      sdk-integration = "-p hellas-sdk --features integration-tests";
      sdk-all = "-p hellas-sdk --all-features";
      executor = "-p hellas-executor --features compute";
      executor-fetch = "-p hellas-executor";
      kernel = "-p hellas-kernel --all-features";
      chain-client-core = chain "client-core";
      chain-proof-verify = chain "proof-verify";
      chain-full-node = chain "full-node";
      chain-test-support = chain "test-support,indexer-api";
      chain-block-view = chain "block-view";
      chain-indexer = chain "indexer";
      chain-indexer-api = chain "indexer-api,integration-tests";
      chain-work-watcher = chain "work-watcher";
    }
    // lib.optionalAttrs (system == "x86_64-linux") {
      cli-only-validator = cliOnly "validator";
      chain-validator = chain "validator";
      chain-validator-integration = chain "validator,integration-tests";
      chain-setup = chain "validator,work-watcher,indexer-api,integration-tests";
    };
  checkSelections = lib.concatMapStrings (
    selection: "cargo check --locked ${selection} --all-targets\n"
  ) (lib.attrValues cargoSelections);

  # Each library on its own, as a dependent builds it: `--lib` leaves out the
  # dev-dependencies, and one package per command keeps workspace siblings
  # from unifying features into it.
  checkLibraries = ''
    for package in $(cargo metadata --locked --no-deps --format-version 1 \
      | jq -r '.packages[] | select(any(.targets[]; any(.kind[]; . == "lib"))) | .name'); do
      cargo check --locked -p "$package" --lib
    done
  '';

  # nixpkgs tests cargo-llvm-cov with its own rustc, whose raw profiles
  # (format 11) its paired llvm-profdata (format 10) cannot read. At run
  # time the tool uses our toolchain's llvm-tools-preview instead.
  cargoLlvmCov = pkgs.cargo-llvm-cov.overrideAttrs { doCheck = false; };

  craneArgs = {
    pname = "hellas";
    version = "0.1.0";
    src = buildSrc;
    strictDeps = true;
    # Git dependencies are fetched at the revisions in Cargo.lock, so bumping
    # them needs no hash update here.
    cargoVendorDir = craneLib.vendorCargoDeps { src = buildSrc; };
    # No --profile flag: `cargo test` keeps the test profile, `cargo check`
    # and `cargo clippy` the dev profile, matching plain cargo in a checkout.
    CARGO_PROFILE = "";
    # Checks never read debug info; skipping it saves compile time and keeps
    # the published dependency artifacts small.
    CARGO_PROFILE_DEV_DEBUG = "0";
    CARGO_PROFILE_TEST_DEBUG = "0";
    inherit (commonArgs)
      SQLX_OFFLINE
      SSL_CERT_FILE
      NIX_SSL_CERT_FILE
      ;
    buildInputs = workspaceBuildInputs;
    nativeBuildInputs = workspaceNativeBuildInputs;
  };

  cargoDeps = craneLib.buildDepsOnly (
    craneArgs
    // {
      # Every configuration the checks build, so none recompiles dependencies.
      buildPhaseCargoCommand = ''
        cargo check --locked --workspace --all-targets --features ${integrationFeatures}
        cargo test --locked --workspace --no-run
        cargo test --locked --workspace --features ${integrationFeatures} --no-run
        ${checkSelections}
      '';
      doCheck = false;
    }
  );

  craneChecks = {
    clippy = craneLib.cargoClippy (
      craneArgs
      // {
        cargoArtifacts = cargoDeps;
        # Terminal check: nothing consumes its target directory.
        doInstallCargoArtifacts = false;
        cargoClippyExtraArgs = clippyArgs;
      }
    );
    # The workspace tests, run once with line-coverage instrumentation. On
    # the validator host the run fails on a failing test; coverage is reported,
    # never enforced. cargo-llvm-cov instruments only workspace crates through
    # its rustc wrapper, so the dependencies in `cargoDeps` stay valid; keeping
    # its target directory at `target` is what lets Cargo reuse them. The
    # output holds lcov.info, summary.json and summary.txt. Other hosts run the
    # same tests uninstrumented.
    unit =
      if pkgs.stdenv.hostPlatform.system == "x86_64-linux" then
        craneLib.mkCargoDerivation (
          craneArgs
          // {
            pname = "hellas-unit";
            cargoArtifacts = cargoDeps;
            # Terminal check: nothing consumes its target directory.
            doInstallCargoArtifacts = false;
            nativeBuildInputs = craneArgs.nativeBuildInputs ++ [
              cargoLlvmCov
              pkgs.cargo-nextest
            ];
            CARGO_LLVM_COV_TARGET_DIR = "target";
            NEXTEST_SHOW_PROGRESS = "counter";
            buildPhaseCargoCommand = ''
              cargo llvm-cov nextest --locked --workspace --no-report
              # nextest does not run doctests; the compile_fail ones pin type safety.
              cargo test --locked --workspace --doc
              mkdir -p "$out"
              cargo llvm-cov report --lcov --output-path "$out/lcov.info"
              cargo llvm-cov report --json --summary-only --output-path "$out/summary.json"
              cargo llvm-cov report --summary-only | tee "$out/summary.txt"
            '';
            installPhaseCommand = "";
          }
        )
      else
        craneLib.cargoTest (
          craneArgs
          // {
            pname = "hellas-unit";
            cargoArtifacts = cargoDeps;
            # Terminal check: nothing consumes its target directory.
            doInstallCargoArtifacts = false;
            cargoTestExtraArgs = "--workspace";
          }
          // lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin {
            RUST_TEST_THREADS = "1";
          }
        );
    # Type-checks each library as a dependent builds it, then every target of
    # every release selection: what Hydra's validation compiles.
    feature-targets = craneLib.mkCargoDerivation (
      craneArgs
      // {
        pname = "hellas-feature-targets";
        cargoArtifacts = cargoDeps;
        # Terminal check: nothing consumes its target directory.
        doInstallCargoArtifacts = false;
        nativeBuildInputs = craneArgs.nativeBuildInputs ++ [ pkgs.buildPackages.jq ];
        buildPhaseCargoCommand = checkLibraries + checkSelections;
        installPhaseCommand = "mkdir -p $out";
      }
    );
    regressions = craneLib.cargoTest (
      craneArgs
      // {
        pname = "hellas-regressions";
        cargoArtifacts = cargoDeps;
        # Terminal check: nothing consumes its target directory.
        doInstallCargoArtifacts = false;
        cargoTestExtraArgs = "--workspace --features ${integrationFeatures} -- --test-threads=1";
      }
    );
  };

  # Stamp the revision only on shipped artifacts. Checks and validation builds
  # leave it out, so a commit that changes no inputs reuses their results.
  revEnv.GIT_REV = builtins.substring 0 12 rev;
in
{
  inherit
    pkgs
    lib
    rustToolchain
    rustPlatform
    workspaceNativeBuildInputs
    commonArgs
    mkHellasPackage
    revEnv
    cargoDeps
    cargoLlvmCov
    craneChecks
    clippyArgs
    cargoSelections
    ;
}
