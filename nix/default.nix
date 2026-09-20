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
    rustToolchain
    workspaceNativeBuildInputs
    ;

  cargoToolPackages = with pkgs; [
    cargo-audit
    cargo-deny
    cargo-fuzz
    cargo-llvm-cov
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

    [bans]
    multiple-versions = "allow"

    [sources]
    allow-git = ["https://github.com/commonwarexyz/monorepo", "https://github.com/hellas-ai/catena-lang"]
  '';
  denyCommand = "cargo deny check --config ${denyConfig}";

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
    inherit
      bufLintCommand
      denyCommand
      pkgs
      lib
      rustToolchain
      workspaceNativeBuildInputs
      ;
    extraChecks = kernel.checks;
  };

  mkHydraSourceCheck =
    {
      name,
      inputs,
      command,
    }:
    pkgs.runCommand "hellas-${name}"
      {
        nativeBuildInputs = inputs;
      }
      ''
        export HOME="$TMPDIR/home"
        export XDG_CACHE_HOME="$TMPDIR/cache"
        mkdir -p "$HOME" "$XDG_CACHE_HOME"
        cd ${nativePkg.buildSrc}
        ${command}
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
      cli = pkgSpec.mkHellasPackage {
        buildNoDefaultFeatures = true;
        # Full network surface, but no local Catena runtime.
        buildFeatures = [
          "chain"
          "gateway"
        ]
        ++ lib.optionals (crossSystem == null) [
          "node"
          "otel"
        ];
      };
      cli-validator = pkgSpec.mkHellasPackage {
        buildNoDefaultFeatures = true;
        buildFeatures = [ "validator" ];
      };
    }
    # Do not advertise the safe local GPU runtime on platforms where the
    # packaged provider toolchain is not yet supported.
    //
      lib.optionalAttrs (crossSystem == null && pkgSpec.pkgs.stdenv.hostPlatform.system == "x86_64-linux")
        {
          cli-catena = pkgSpec.mkHellasPackage {
            buildNoDefaultFeatures = true;
            buildFeatures = [
              "evaluate"
              "otel"
            ];
          };
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
      // {
        pname = "hellas-rpc-wasm";
        cargoBuildFlags = [
          "-p"
          "hellas-rpc"
        ];
        CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
        # wasm tests need wasm-bindgen-test infra (deferred). buildRustPackage's
        # canExecute heuristic doesn't see our CARGO_BUILD_TARGET override, so
        # without this it'd try to invoke `cargo test` against wasm and fail.
        doCheck = false;
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
      };
      dockerCuda = import ./docker.nix {
        inherit pkgs rustToolchain;
        cli = nativePackages.cli-catena;
        backend = "cuda";
      };
      dockerHip = import ./docker.nix {
        inherit pkgs rustToolchain;
        cli = nativePackages.cli-catena;
        backend = "hip";
      };

      nixosTests = lib.optionalAttrs isX86_64Linux (
        import ./tests {
          inherit self pkgs lib;
          package = nativePackages.cli-catena;
          networkPackage = nativePackages.cli;
          validatorPackage = nativePackages.cli-validator;
        }
      );
    in
    {
      packages = {
        docker = docker.image;
      }
      // lib.optionalAttrs isX86_64Linux {
        docker-cuda = dockerCuda.image;
        docker-hip = dockerHip.image;
      };

      apps = {
        "docker-push" = {
          type = "app";
          program = "${docker.push}/bin/docker-push";
          meta.description = "Push the Hellas network-node Docker image";
        };
      }
      // lib.optionalAttrs isX86_64Linux {
        "docker-push-all" = {
          type = "app";
          program = "${
            pkgs.writeShellApplication {
              name = "hellas-docker-push-all";
              text = ''
                ${docker.push}/bin/docker-push "$@"
                ${dockerCuda.push}/bin/docker-push "$@"
                ${dockerHip.push}/bin/docker-push "$@"
              '';
            }
          }/bin/hellas-docker-push-all";
          meta.description = "Push the Hellas network, CUDA, and HIP Docker images";
        };
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
          packages = devShellPackages ++ [ pkgs.hellasLib.rocmToolkit ];
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
            export LD_LIBRARY_PATH=${pkgs.hellasLib.rocmToolkit}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
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

  hydraLints = {
    "no-catgrad-lock" = noCatgradLock;

    sort = mkHydraSourceCheck {
      name = "check-sort";
      inputs = [ pkgs.cargo-sort ];
      # Taplo owns TOML layout; cargo-sort owns table/key ordering.
      command = "cargo-sort --workspace --check --no-format";
    };

    fmt = mkHydraSourceCheck {
      name = "check-fmt";
      inputs = [ rustToolchain ];
      command = "cargo fmt --all -- --check";
    };

    clippy = nativePkg.mkHellasPackage {
      pname = "hellas-check-clippy";
      cargoBuildType = "debug";
      buildPhase = ''
        runHook preBuild
        cargo clippy --workspace --all-targets --offline -- -D warnings
        runHook postBuild
      '';
      doCheck = false;
      installPhase = ''
        mkdir -p "$out"
        touch "$out/passed"
      '';
    };

    taplo = mkHydraSourceCheck {
      name = "check-taplo";
      inputs = [ pkgs.taplo ];
      command = "taplo fmt --option 'indent_string=    ' --check '*.toml' 'crates/**/Cargo.toml'";
    };

    buf = mkHydraSourceCheck {
      name = "check-buf";
      inputs = [ pkgs.buf ];
      command = bufLintCommand;
    };

    deadnix = mkHydraSourceCheck {
      name = "check-deadnix";
      inputs = [ pkgs.deadnix ];
      command = ''
        shopt -s globstar
        deadnix --fail flake.nix nix/**/*.nix
      '';
    };

    statix = mkHydraSourceCheck {
      name = "check-statix";
      inputs = [ pkgs.statix ];
      command = "statix check .";
    };

    nixfmt = mkHydraSourceCheck {
      name = "check-nixfmt";
      inputs = [ pkgs.nixfmt ];
      command = ''
        shopt -s globstar
        nixfmt --check flake.nix nix/**/*.nix
      '';
    };

    wasm-rpc = hellasRpcWasm;
  };

  hydraPackages = {
    inherit (nativePackages) cli;
  }
  // lib.optionalAttrs isX86_64Linux {
    # Validators are deployed only on x86; ARM workers build the client/node CLI.
    inherit (nativePackages) cli-catena cli-validator;
    static-x86_64 = crossPackages.cross-x86_64-linux-musl-cli;
    static-aarch64 = crossPackages.cross-aarch64-linux-musl-cli;
    inherit (linuxOutputs.packages) docker;
    "hellas-rpc-wasm" = hellasRpcWasm;
  };

  hydraE2e = linuxOutputs.nixosTests or { };

  hydraRequired = pkgs.releaseTools.aggregate {
    name = "hellas-required";
    constituents = [
      defaultDevShell
    ]
    ++ lib.attrValues hydraLints
    ++ lib.attrValues hydraPackages
    ++ lib.attrValues hydraE2e;
  };
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
      meta.description = "Run local checks and dependency audits";
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
  ci = { inherit (ci) checks builds; };

  # nixosTests are also surfaced under `checks` so `nix flake check` runs them.
  checks = (linuxOutputs.nixosTests or { }) // {
    "no-catgrad-lock" = noCatgradLock;
  };
  nixosTests = linuxOutputs.nixosTests or { };

  hydraJobs = {
    devShell = defaultDevShell;
    lints = hydraLints;
    packages = hydraPackages;
    required = hydraRequired;
  }
  // lib.optionalAttrs isX86_64Linux {
    e2e = hydraE2e;
  };
}
