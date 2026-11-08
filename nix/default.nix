{
  self,
  system,
  nixpkgs,
  rust-overlay,
}:
let
  nativePkg = import ./package.nix {
    inherit
      self
      system
      nixpkgs
      rust-overlay
      ;
  };
  inherit (nativePkg)
    pkgs
    lib
    cargoLlvmCov
    rustToolchain
    workspaceNativeBuildInputs
    ;

  cargoToolPackages = with pkgs; [
    cargo-audit
    cargo-deny
    cargo-fuzz
    cargoLlvmCov
    cargo-mutants
    cargo-nextest
    cargo-outdated
    cargo-sort
    cargo-watch
  ];

  commonToolPackages = with pkgs; [
    jq
    just
    nixfmt
    taplo
  ];

  # Buf's standard RPC naming rules assume generated gRPC APIs. Hellas uses
  # service names in transport identities and deliberately shares protocol
  # objects between methods, so those cosmetic rules would change the wire
  # protocol or add one-field wrappers. Keep the exceptions with the check
  # that needs them instead of a repository-root tool configuration file.
  bufLintConfig = builtins.toJSON {
    version = "v2";
    modules = [ { path = "proto"; } ];
    lint = {
      use = [ "STANDARD" ];
      except = [
        "SERVICE_SUFFIX"
        "RPC_RESPONSE_STANDARD_NAME"
        "RPC_REQUEST_STANDARD_NAME"
        "RPC_REQUEST_RESPONSE_UNIQUE"
      ];
    };
  };
  bufLintCommand = "buf lint --config ${lib.escapeShellArg bufLintConfig}";

  denyConfig = pkgs.writeText "hellas-deny.toml" ''
    [advisories]
    ignore = [
      { id = "RUSTSEC-2024-0436", reason = "Transitive through commonware/gemm; no safe upgrade is available." },
      { id = "RUSTSEC-2025-0141", reason = "Transitive through upstream catena-lang; bincode 1.3.3 is final and no safe upgrade is available." },
    ]

    [licenses]
    allow = [
      "Apache-2.0",
      "Apache-2.0 WITH LLVM-exception",
      "BSD-1-Clause",
      "BSD-2-Clause",
      "BSD-3-Clause",
      "BSL-1.0",
      "CC0-1.0",
      "CDLA-Permissive-2.0",
      "ISC",
      "MIT",
      "MIT-0",
      "MPL-2.0",
      "Unicode-3.0",
      "Unlicense",
      "Zlib",
    ]
    # catena-models is hellas-ai's own crate and declares no license.
    exceptions = [
      { crate = "catena-models", allow = ["LicenseRef-hellas-ai"] },
    ]

    [[licenses.clarify]]
    crate = "catena-models"
    expression = "LicenseRef-hellas-ai"
    license-files = []

    [bans]
    multiple-versions = "allow"

    [sources]
    allow-git = ["https://github.com/georgewhewell/commonware-monorepo", "https://github.com/hellas-ai/catena-lang", "https://github.com/hellas-ai/catena-models"]
  '';
  denyCommand = "cargo deny --config ${denyConfig} check";

  kernel = import ./kernel.nix {
    inherit
      pkgs
      lib
      rustToolchain
      cargoToolPackages
      commonToolPackages
      ;
  };

  devShellPackages =
    (with pkgs; [
      rustToolchain
      perl
      pkg-config
      protobuf
      llvmPackages.lld
      pre-commit
      protobuf-language-server
      gh
      cargo-machete
      cargo-udeps
      skopeo
      sqlx-cli
    ])
    ++ cargoToolPackages
    ++ commonToolPackages;

  envShellHook = ''
    if [ -f .env ]; then
      set -a
      source .env
      set +a
    fi
  '';

  defaultDevShell = pkgs.mkShell {
    packages = devShellPackages;
    shellHook = envShellHook;
  };

  ci = import ./ci.nix {
    inherit (nativePkg) clippyArgs cargoSelections;
    inherit
      bufLintCommand
      denyCommand
      pkgs
      lib
      rustToolchain
      workspaceNativeBuildInputs
      ;
    cargoDeps = nativePackages.cli.cargoDeps;
    extraChecks = kernel.checks;
  };

  # Whole-tree lints (workflows, Nix files, TOML outside the crates) as
  # derivations. Each runs the same ci.nix app that `nix run .#check-<name>`
  # runs, so the two cannot drift apart.
  mkHydraSourceCheck =
    check:
    pkgs.runCommand "hellas-${check.name}" { } ''
      export HOME="$TMPDIR/home"
      export XDG_CACHE_HOME="$TMPDIR/cache"
      mkdir -p "$HOME" "$XDG_CACHE_HOME"
      cd ${self}
      ${lib.getExe check}
      touch "$out"
    '';

  packagesFor =
    crossSystem:
    let
      pkgSpec = import ./package.nix {
        inherit
          self
          system
          nixpkgs
          rust-overlay
          crossSystem
          ;
      };
    in
    {
      cli = lib.makeOverridable (
        {
          otel ? false,
        }:
        pkgSpec.mkHellasPackage (
          pkgSpec.revEnv
          // {
            buildNoDefaultFeatures = true;
            # Client, gateway and daemon share one native composition.
            buildFeatures = lib.optional otel "otel";
          }
        )
      ) { };
      cli-validator = lib.makeOverridable (
        {
          otel ? false,
        }:
        pkgSpec.mkHellasPackage (
          pkgSpec.revEnv
          // {
            buildNoDefaultFeatures = true;
            buildFeatures = [ "validator" ] ++ lib.optional otel "otel";
          }
        )
      ) { };
    };

  crossTargets = {
    # The store's replacement-resistant file identity uses Unix device,
    # inode, mtime, and ctime metadata. Do not advertise Windows until an
    # equally strong platform-specific identity has an implementation/tests.
    "aarch64-linux" = nixpkgs.lib.systems.examples.aarch64-multiplatform;
    "riscv64-linux" = nixpkgs.lib.systems.examples.riscv64;
    "x86_64-linux-musl" = nixpkgs.lib.systems.examples.musl64 // {
      isStatic = true;
    };
    "aarch64-linux-musl" = nixpkgs.lib.systems.examples.aarch64-multiplatform-musl // {
      isStatic = true;
    };
  };

  nativePackages = packagesFor null;

  # Windows (x86_64-pc-windows-gnu, mingw-w64) is CI-only. Hydra cross-builds
  # it and runs it on a real Windows host (windowsJobs), but it stays out of
  # `packages`, `crossTargets` and the required aggregate until the store has
  # a Windows file identity as strong as the Unix one (see crossTargets).
  windowsPackages = packagesFor nixpkgs.lib.systems.examples.mingwW64;
  isX86_64Linux = pkgs.stdenv.hostPlatform.system == "x86_64-linux";
  # Flat `cross-<target>-<name>` packages. Nested `packages.<sys>.cross.<target>.<name>`
  # violates the flake schema (each entry must be a derivation), which `nix flake check`
  # rightly flags.
  crossPackages = lib.concatMapAttrs (
    tgt: lib.mapAttrs' (name: pkg: lib.nameValuePair "cross-${tgt}-${name}" pkg)
  ) (lib.mapAttrs (_: packagesFor) crossTargets);

  # Wasm build of hellas-rpc. Native rustToolchain with an additional wasm32
  # target — not a nix crossSystem (that's for OS-level cross), just a rust
  # target. Output is whatever cargo produces in
  # `target/wasm32-unknown-unknown/release/` (rlib today; .wasm if/when the
  # crate adds `crate-type = ["cdylib"]`).
  hellasRpcWasm =
    let
      wasmRust = rustToolchain.override { targets = [ "wasm32-unknown-unknown" ]; };
      wasmPlatform = pkgs.makeRustPlatform {
        rustc = wasmRust;
        cargo = wasmRust;
        stdenv = pkgs.clangStdenv;
      };
    in
    wasmPlatform.buildRustPackage (
      nativePkg.commonArgs
      // nativePkg.revEnv
      // {
        pname = "hellas-rpc-wasm";
        # cargoBuildHook passes the native --target explicitly, which overrides
        # CARGO_BUILD_TARGET. Select the wasm target in the actual command.
        buildPhase = ''
          runHook preBuild
          cargo build --offline --release --target wasm32-unknown-unknown -p hellas-rpc --no-default-features --jobs "$NIX_BUILD_CORES"
          runHook postBuild
        '';
        # Wasm tests need a wasm test runtime.
        doCheck = false;
        dontStrip = true;
        separateDebugInfo = false;
        # The default Cargo install hook installs executables, not this rlib.
        installPhase = ''
          runHook preInstall
          install -Dm644 target/wasm32-unknown-unknown/release/libhellas_rpc.rlib "$out/lib/libhellas_rpc.rlib"
          mkdir -p "$out/lib/deps"
          cp target/wasm32-unknown-unknown/release/deps/*.rlib "$out/lib/deps/"
          runHook postInstall
        '';
      }
    );

  linuxOutputs = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
    let
      docker = import ./docker.nix {
        inherit
          pkgs
          rustToolchain
          ;
        inherit (nativePackages) cli;
        revision = self.rev or self.dirtyRev or "unknown";
      };
      dockerCuda = import ./docker.nix {
        inherit pkgs rustToolchain;
        inherit (nativePackages) cli;
        backend = "cuda";
        revision = self.rev or self.dirtyRev or "unknown";
      };
      dockerHip = import ./docker.nix {
        inherit pkgs rustToolchain;
        inherit (nativePackages) cli;
        backend = "hip";
        revision = self.rev or self.dirtyRev or "unknown";
      };

      nixosTests = lib.optionalAttrs isX86_64Linux (
        import ./tests {
          inherit self pkgs lib;
          package = nativePackages.cli;
          validatorPackage = nativePackages.cli-validator;
        }
      );
    in
    {
      packages = {
        docker = docker.image;
        docker-otel =
          (import ./docker.nix {
            inherit pkgs rustToolchain;
            cli = nativePackages.cli.override { otel = true; };
            revision = self.rev or self.dirtyRev or "unknown";
          }).image;
      }
      // lib.optionalAttrs isX86_64Linux {
        docker-cuda = dockerCuda.image;
        docker-hip = dockerHip.image;
      };

      apps.publish = {
        type = "app";
        program = "${import ./publish.nix { inherit pkgs; }}/bin/hellas-publish";
        meta.description = "Publish verified Hydra artifacts to ghcr.io and GitHub Releases";
      };

      devShells = lib.optionalAttrs isX86_64Linux {
        cuda = pkgs.mkShellNoCC {
          packages = devShellPackages ++ [
            pkgs.hellasLib.cudaToolkit
            pkgs.cudaPackages.backendStdenv.cc
          ];
          shellHook = envShellHook + ''
            export CUDA_PATH=${pkgs.hellasLib.cudaToolkit}
            export NVCC_CCBIN=${pkgs.cudaPackages.backendStdenv.cc}/bin/c++
            export LD_LIBRARY_PATH=${pkgs.hellasLib.cudaToolkit}/lib:/run/opengl-driver/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
          '';
        };
        rocm = pkgs.mkShellNoCC {
          # The toolkit is reached through PATH/ROCM_PATH only. As a package its lib/
          # (which carries its own glibc) would enter NIX_LDFLAGS and every
          # binary's RUNPATH, aborting Nix-built programs at startup.
          packages = devShellPackages;
          shellHook = envShellHook + ''
            # hipcc's setup selects its clang as the host C compiler. That
            # compiler emits newer LLVM LTO objects which this Rust toolchain's
            # lld cannot consume (notably while building alloca's C shim).
            # Keep ordinary build scripts on nixpkgs' wrapped host compiler;
            # Catena still reaches ROCm through hipcc and HIP_CLANG_PATH.
            export CC=${pkgs.stdenv.cc}/bin/cc
            export CXX=${pkgs.stdenv.cc}/bin/c++
            export ROCM_PATH=${pkgs.hellasLib.rocmToolkit}
            export HIP_PATH=${pkgs.hellasLib.rocmToolkit}
            export HIP_CLANG_PATH=${pkgs.hellasLib.rocmToolkit}/bin
            export DEVICE_LIB_PATH=${pkgs.hellasLib.rocmToolkit}/amdgcn/bitcode
            export HIP_FLAGS="--rocm-path=${pkgs.hellasLib.rocmToolkit} --rocm-device-lib-path=${pkgs.hellasLib.rocmToolkit}/amdgcn/bitcode"
            export PATH=$PATH:${pkgs.hellasLib.rocmToolkit}/bin
          '';
        };
      };

      inherit nixosTests;
    }
  );

  noCatgradLock =
    pkgs.runCommand "hellas-no-catgrad-lock" { nativeBuildInputs = [ pkgs.gnugrep ]; }
      ''
        if grep -Eqi 'catgrad' ${../flake.lock}; then
          echo "flake.lock still contains Catgrad after the Catena cutover" >&2
          exit 1
        fi
        touch "$out"
      '';

  hydraLints =
    lib.genAttrs [
      "actions"
      "sort"
      "fmt"
      "taplo"
      "buf"
      "deadnix"
      "statix"
      "nixfmt"
    ] (name: mkHydraSourceCheck ci.checks.${name})
    // {
      "no-catgrad-lock" = noCatgradLock;
      inherit (nativePkg.craneChecks) clippy;
    };

  hydraUnit = nativePkg.craneChecks.unit;

in
{
  packages =
    nativePackages
    // crossPackages
    // {
      default = nativePackages.cli;
      "hellas-rpc-wasm" = hellasRpcWasm;
    }
    // (linuxOutputs.packages or { });

  apps = {
    check = {
      type = "app";
      program = lib.getExe ci.checkAll;
      meta.description = "Run PR lints and unit tests";
    };
    check-lints = {
      type = "app";
      program = lib.getExe ci.checkLints;
      meta.description = "Run PR lints";
    };
    check-release = {
      type = "app";
      program = lib.getExe ci.checkRelease;
      meta.description = "Run the full release test and feature-check suite";
    };
    fix = {
      type = "app";
      program = lib.getExe ci.fixAll;
      meta.description = "Apply auto-fixes (fmt, sort, clippy)";
    };
  }
  // kernel.apps
  // (lib.mapAttrs' (
    name: pkg:
    lib.nameValuePair "check-${name}" {
      type = "app";
      program = lib.getExe pkg;
      meta.description = "Run the ${name} check";
    }
  ) ci.checks)
  // (linuxOutputs.apps or { });

  devShells = {
    default = defaultDevShell;
    kernel = kernel.devShell;
  }
  // (linuxOutputs.devShells or { });

  formatter = pkgs.nixfmt;

  # Data exposed for local matrix runners:
  #   .checks -> { name -> derivation }
  #   .builds -> { name -> attrPath }
  ci = {
    checks = ci.mergeChecks;
    releaseChecks = ci.checks;
    inherit (ci) builds;
  };

  checks = hydraLints // {
    unit = hydraUnit;
    inherit (nativePkg.craneChecks) regressions feature-targets;
    # Published so later builds substitute compiled dependencies.
    cargo-deps = nativePkg.cargoDeps;
  };
  nixosTests = linuxOutputs.nixosTests or { };

  # Evaluated by the explicit Windows jobset in infra services/ci/hydra.nix.
  windowsJobs = lib.optionalAttrs isX86_64Linux {
    inherit (windowsPackages) cli;
    # Runs on the `wsl` builder (NixOS-WSL inside a Windows VM), whose sandbox
    # exposes WSL interop. Interop translates the working directory to a
    # Windows path, so exec from `/` -- the sandbox-only /build fails EINVAL.
    smoke =
      pkgs.runCommand "hellas-cli-windows-smoke"
        {
          requiredSystemFeatures = [ "wsl" ];
          exe = "${windowsPackages.cli}/bin/hellas.exe";
        }
        ''
          cd /
          export WSL_INTEROP=/run/WSL/1_interop
          if ! "$exe" --version >"$TMPDIR/version" 2>&1; then
            cat "$TMPDIR/version"
            exit 1
          fi
          cat "$TMPDIR/version"
          grep -q . "$TMPDIR/version"
          cp "$TMPDIR/version" "$out"
        '';
  };

  releaseJobs = import ./releases.nix {
    inherit
      self
      pkgs
      lib
      system
      nativePkg
      nativePackages
      crossPackages
      linuxOutputs
      hydraLints
      hydraUnit
      hellasRpcWasm
      ci
      ;
  };
}
