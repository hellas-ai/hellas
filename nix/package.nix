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
      hellasLib = import ./lib {
        pkgs = final;
        inherit (self.inputs) nix-strix-halo;
      };
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

  rustToolchain =
    (pkgs.buildPackages.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml).override
      {
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

  buildSrc = self;

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
  };

  commonArgs = {
    pname = "hellas";
    version = "0.1.0";
    src = buildSrc;
    cargoLock = {
      lockFile = ../Cargo.lock;
      outputHashes = {
        "catena-lang-0.1.0" = "sha256-NzPlFhyxivNYgChgFNMsDte/N8roD70LwEqFh1FLef0=";
        "commonware-actor-2026.7.0" = "sha256-SzlE5sQufUH2ukJ5Job5mEkIuF6m87hU9oLmeaEDFLE=";
      };
    };
    inherit stdenv;
    auditable = false;
    RUST_MIN_STACK = "16777216";
    GIT_REV = builtins.substring 0 12 rev;
    SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
    NIX_SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
    buildInputs = workspaceBuildInputs;
    nativeBuildInputs = workspaceNativeBuildInputs;
    # noq-udp 1.1.0 assumes cmsghdr has its timestamp payload's alignment.
    # On musl that panics on the first received UDP packet. Keep the backport
    # limited to musl packages until the upstream fix is released.
    postPatch = lib.optionalString pkgs.stdenv.hostPlatform.isMusl ''
      patch -d "$cargoDepsCopy/noq-udp-1.1.0" -p1 < ${./noq-udp-musl.patch}
    '';
    # CLI unit tests do not exercise UDP receive. Run the cloud crate's real
    # iroh enrollment test wherever this builder can execute the musl target.
    postBuild =
      lib.optionalString
        (pkgs.stdenv.hostPlatform.isMusl && pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform)
        ''
          timeout 120 cargo test --offline --release --target ${targetTriple} \
            -p hellas-cloud --test management \
            enrollment_requires_owner_confirmation_and_cannot_be_silently_replaced -- --exact
        '';
    checkInputs = with pkgs; [ cargo-outdated ];
    separateDebugInfo = true;
    # stdenv's default stripDebugList only does --strip-debug on bin/;
    # stripAllList promotes it to --strip-all so .symtab goes too.
    stripAllList = [ "bin" ];
    meta.mainProgram = "hellas-cli";
  }
  // crossEnv;

  mkHellasPackage = overrides: rustPlatform.buildRustPackage (commonArgs // overrides);
in
{
  inherit
    pkgs
    lib
    rustToolchain
    rustPlatform
    workspaceNativeBuildInputs
    buildSrc
    commonArgs
    mkHellasPackage
    ;
}
