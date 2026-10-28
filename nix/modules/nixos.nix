{
  self,
  hellas ? import ./hellas.nix { inherit self; },
}:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkIf mkOption types;
  cfg = config.services.hellas;
  inherit (cfg) gateway;
  hellasLib = import ../lib {
    inherit pkgs;
    inherit (self.inputs) nix-strix-halo;
  };
  normalizeRuntimePath = hellas.lexicallyNormalizeAbsolutePath lib;
  pathWithin =
    root: path:
    let
      normalizedRoot = normalizeRuntimePath root;
      normalizedPath = normalizeRuntimePath path;
    in
    normalizedRoot == "/"
    || normalizedPath == normalizedRoot
    || lib.hasPrefix "${normalizedRoot}/" normalizedPath;
  pathsOverlap = first: second: pathWithin first second || pathWithin second first;
  outsideManagedRoots = roots: path: !(lib.any (root: pathWithin root path) roots);
  providerManagedWritableRoots = [
    hellasLib.defaultStateDir
    "/var/cache/hellas"
  ];
  gatewayManagedWritableRoots = [
    "/var/lib/hellas-gateway"
    "/var/cache/hellas-gateway"
  ];
  providerContentPaths = lib.unique (map normalizeRuntimePath (cfg.content ++ cfg.contentRoots));
  providerWritablePaths = lib.unique (
    lib.optional (
      cfg.contentIndex != null
      && outsideManagedRoots providerManagedWritableRoots (
        builtins.dirOf (normalizeRuntimePath cfg.contentIndex)
      )
    ) (builtins.dirOf (normalizeRuntimePath cfg.contentIndex))
  );
  gatewayWritablePaths = lib.unique (
    map normalizeRuntimePath gateway.paidWorkJournalRoots
    ++ lib.optional (
      gateway.authorityJournal != null
      && outsideManagedRoots gatewayManagedWritableRoots gateway.authorityJournal
    ) (normalizeRuntimePath gateway.authorityJournal)
  );
  providerWritablePathsAreDisjoint = lib.all (
    writable: lib.all (content: !pathsOverlap writable content) providerContentPaths
  ) providerWritablePaths;
  providerCatenaConfigured = hellas.catenaConfigured cfg;
  providerLocalExecutionEnabled = cfg.workConfigFile != null && hellas.catenaConfigured cfg;
  providerGpuConfigured = hellas.catenaPlatform pkgs && providerLocalExecutionEnabled;
  defaultGpuSessionAssetBytes = 128 * 1024 * 1024 * 1024;
  effectiveGpuSessionAssetBytes =
    if cfg.gpuSessionAssetBytes == null then defaultGpuSessionAssetBytes else cfg.gpuSessionAssetBytes;
  inherit (hellasLib) rocmToolkit cudaToolkit;
  nvidiaDriverEnabled = builtins.elem "nvidia" config.services.xserver.videoDrivers;
  useCuda = cfg.gpuBackend == "cuda" || (cfg.gpuBackend == null && nvidiaDriverEnabled);
  useHip = cfg.gpuBackend == "hip" || (cfg.gpuBackend == null && !nvidiaDriverEnabled);
  gpuPackages =
    lib.optionals useHip [ rocmToolkit ]
    ++ lib.optionals useCuda [
      cudaToolkit
      pkgs.cudaPackages.backendStdenv.cc
    ];
  # The ROCm toolkit's lib/ carries its own glibc, which would replace the
  # binary's loader-matched libc; HIP is found via ROCM_PATH/HIP_PATH instead.
  gpuLibraryPath =
    lib.optionals useCuda [
      "${cudaToolkit}/lib"
      "/run/opengl-driver/lib"
    ]
    ++ lib.optional (cfg.environment ? LD_LIBRARY_PATH) (toString cfg.environment.LD_LIBRARY_PATH);
  gpuEnvironment =
    lib.optionalAttrs useHip rocmEnvironment
    // lib.optionalAttrs useCuda {
      CUDA_PATH = cudaToolkit;
      NVCC_CCBIN = "${pkgs.cudaPackages.backendStdenv.cc}/bin/c++";
    }
    // lib.optionalAttrs (gpuLibraryPath != [ ]) {
      LD_LIBRARY_PATH = lib.concatStringsSep ":" gpuLibraryPath;
    };
  rocmEnvironment = {
    ROCM_PATH = rocmToolkit;
    HIP_PATH = rocmToolkit;
    HIP_CLANG_PATH = "${rocmToolkit}/bin";
    DEVICE_LIB_PATH = "${rocmToolkit}/amdgcn/bitcode";
    HIP_FLAGS = "--rocm-path=${rocmToolkit} --rocm-device-lib-path=${rocmToolkit}/amdgcn/bitcode";
  };
  outsideStorePath = hellas.runtimePathIsOutsideStore lib;
  outsideStoreString = hellas.runtimeStringIsOutsideStore lib;
  userEnvironmentStrings = lib.filter builtins.isString (lib.attrValues cfg.environment);
  providerRuntimePaths = [
    cfg.identityPath
  ]
  ++ cfg.content
  ++ cfg.contentRoots
  ++ lib.optional (cfg.contentIndex != null) cfg.contentIndex
  ++ lib.optional (cfg.workConfigFile != null) cfg.workConfigFile
  ++ lib.optional (cfg.passkey != null) cfg.passkey
  ++ lib.optional (cfg.fetchConfigFile != null) cfg.fetchConfigFile
  ++ lib.optional (cfg.environmentFile != null) cfg.environmentFile;
  gatewayRuntimePaths = lib.optionals gateway.enable (
    lib.optional (gateway.textModel != null) gateway.textModel
    ++ [ gateway.identityPath ]
    ++ lib.optional (gateway.environmentFile != null) gateway.environmentFile
    ++ lib.optional (gateway.paidWorkConfig != null) gateway.paidWorkConfig
    ++ lib.optional (gateway.trustStore != null) gateway.trustStore
    ++ lib.optional (gateway.workProfile != null) gateway.workProfile
    ++ lib.optional (gateway.passkey != null) gateway.passkey
    ++ lib.optional (gateway.gatewayProfile != null) gateway.gatewayProfile
    ++ gateway.paidWorkJournalRoots
    ++ lib.optional (gateway.authorityJournal != null) gateway.authorityJournal
  );
  gpuDeviceAccess = {
    # DynamicUser does not inherit an interactive user's device groups.
    # The cgroup rule covers every DRM render node without baking a
    # device number into the module; /dev/kfd is ROCm's compute device.
    SupplementaryGroups = [
      "render"
      "video"
    ];
    DeviceAllow =
      lib.optionals useHip [
        "/dev/kfd rw"
        "char-drm rw"
      ]
      ++ lib.optionals useCuda [
        "char-nvidia-frontend rw"
        "char-nvidiactl rw"
        "char-nvidia-uvm rw"
        "char-nvidia-caps rw"
      ];
  };
in
{
  options.services.hellas =
    hellas.commonOptions {
      inherit lib;
      package = (hellas.normalCliPackage pkgs).override { otel = cfg.otel.enable; };
      inherit (cfg) otel;
      packageDescription = ''
        The hellas CLI used to run the serve daemon. Local Catena execution is
        currently available only on x86_64-linux because the packaged provider
        runtime currently targets that platform.
      '';
    }
    // hellas.serveOptions { inherit lib pkgs; }
    // {
      gateway = hellas.gatewayOptions { inherit lib; } // {
        package = mkOption {
          type = types.package;
          default = cfg.package;
          defaultText = lib.literalMD ''
            `services.hellas.package`: the platform's default node CLI.
          '';
          description = "The hellas CLI used to run the HTTP gateway.";
        };
      };
      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the Hellas UDP listen port in the firewall.";
      };
      environmentFile = mkOption {
        type = types.nullOr (types.strMatching "/.*");
        default = null;
        example = "/run/secrets/hellas-provider.env";
        description = ''
          Optional systemd EnvironmentFile for provider-only secrets such as
          an OpenAI Fetch API key. Its contents remain outside the Nix store.
          Pass a plain absolute path; never interpolate a Nix path or a
          builtins.readFile result, which would copy or read the secret during
          evaluation before this module can validate the path.
        '';
      };
      memoryMaxBytes = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        example = 137438953472;
        description = ''
          Optional systemd MemoryMax byte ceiling for the complete provider
          unit. When set, it must exceed the effective gpuSessionAssetBytes
          value (128 GiB when that option is null) so the runtime, compiler,
          child workers, and non-asset allocations have headroom. The service
          never uses swap and an OOM kills the whole unit before
          Restart=on-failure restarts it.
        '';
      };
    };

  config = mkIf (cfg.enable || gateway.enable) {
    assertions = [
      {
        assertion = !gateway.enable || gateway.gatewayProfile != null;
        message = "services.hellas.gateway requires gatewayProfile for its provisioned HTTP authority.";
      }
      {
        assertion = pkgs.stdenv.hostPlatform.isLinux;
        message = "services.hellas is only supported on Linux.";
      }
      {
        assertion = !cfg.enable || cfg.assurance == "producer-signed";
        message = "services.hellas cannot serve apple-app-attest assurance on NixOS; Apple App Attest requires a Secure Enclave provider.";
      }
      {
        assertion = lib.all outsideStorePath (providerRuntimePaths ++ gatewayRuntimePaths);
        message = "services.hellas content, identity, artifact store, environment, work config, Fetch config, EnvironmentFile, and text model paths must be runtime data outside the Nix store.";
      }
      {
        assertion = lib.all outsideStoreString userEnvironmentStrings;
        message = "services.hellas.environment string values must not use file: URIs or point into the Nix store; use runtime paths or an EnvironmentFile for provider and gateway runtime data.";
      }
      {
        assertion = !cfg.enable || lib.all (path: path != "/") providerWritablePaths;
        message = "services.hellas the parent of contentIndex must not expose the filesystem root as writable.";
      }
      {
        assertion = !gateway.enable || lib.all (path: path != "/") gatewayWritablePaths;
        message = "services.hellas.gateway writable journal paths must not expose the filesystem root as writable.";
      }
      {
        assertion = !cfg.enable || providerWritablePathsAreDisjoint;
        message = "services.hellas external contentIndex parent must be dedicated writable locations outside content and contentRoots.";
      }
      {
        assertion = cfg.memoryMaxBytes == null || cfg.memoryMaxBytes > effectiveGpuSessionAssetBytes;
        message = "services.hellas.memoryMaxBytes must exceed gpuSessionAssetBytes so the provider has non-asset memory headroom.";
      }
      {
        assertion = hellas.extraArgsAreSafe lib hellas.protectedServeExtraArgs cfg.extraArgs;
        message = "services.hellas.extraArgs may not override module-managed runtime, content, identity, trust, or configuration flags; use the corresponding option instead.";
      }
      {
        assertion = hellas.extraArgsAreSafe lib hellas.protectedGatewayExtraArgs gateway.extraArgs;
        message = "services.hellas.gateway.extraArgs may not override module-managed runtime, content, identity, trust, or configuration flags; use the corresponding option instead.";
      }
      {
        assertion = hellas.catenaPlatform pkgs || !providerCatenaConfigured;
        message = "Local Catena execution is supported only on x86_64-linux; omit content, contentRoots, contentIndex, GPU resource bounds on this platform.";
      }
      {
        assertion = !gateway.enable || gateway.textModel != null || gateway.responsesBackend != "hellas";
        message = "services.hellas.gateway.textModel is required for native inference.";
      }
      {
        assertion = gateway.nodeAddrs == [ ] || gateway.nodeId != null;
        message = "services.hellas.gateway.nodeAddrs requires nodeId.";
      }
      {
        assertion =
          !gateway.enable
          || gateway.offer != null

          || gateway.paidWorkConfig != null
          || (
            gateway.responsesBackend == "proxy"

            && gateway.nodeId == null

          );
        message = "services.hellas.gateway execution requires an offer or paidWorkConfig.";
      }
      {
        assertion =
          gateway.paidWorkConfig == null
          || (
            gateway.nodeId == null
            && gateway.offer == null
            && gateway.trustStore == null
            && gateway.trustPolicy == null
            && gateway.responsesBackend == "hellas"
            && gateway.assurance == "producer-signed"
          );
        message = "services.hellas.gateway.paidWorkConfig requires remote producer-signed Hellas execution without target overrides.";
      }
      {
        assertion =
          gateway.responsesBackend != "fetch" || gateway.responsesFetchExecutionEnvironment != null;
        message = "services.hellas.gateway.responsesFetchExecutionEnvironment is required when responsesBackend = \"fetch\".";
      }
      {
        assertion = !gateway.enable || (gateway.trustStore == null) == (gateway.trustPolicy == null);
        message = "services.hellas.gateway.trustStore and trustPolicy must be configured together.";
      }
      {
        assertion =
          !gateway.enable
          || gateway.offer == null
          || (gateway.trustPolicy != null && gateway.workProfile != null && gateway.passkey != null);
        message = "services.hellas.gateway grant execution requires trustPolicy, workProfile and passkey.";
      }
      {
        assertion = gateway.offer == null || gateway.paidWorkConfig == null;
        message = "services.hellas.gateway must select only one funding target.";
      }
    ];

    systemd.services.hellas = mkIf cfg.enable {
      description = "Hellas node server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      unitConfig = lib.optionalAttrs (providerRuntimePaths != [ ]) {
        # Pull in external model/content mounts even when they are declared
        # `nofail`; starting against an empty mountpoint would index the wrong
        # filesystem and make an otherwise satisfiable environment disappear.
        RequiresMountsFor = providerRuntimePaths;
      };
      path = lib.optionals providerGpuConfigured gpuPackages;
      environment = hellas.renderEnvironment (
        hellas.mkOtelEnv {
          inherit lib;
          inherit (cfg) otel;
        }
        // cfg.environment
        // {
          HOME = hellasLib.defaultStateDir;
          # Catena compiles generated shared objects below TMPDIR and dlopens
          # them. CacheDirectory is deliberately mounted noexec for a
          # DynamicUser, so use the private, ephemeral RuntimeDirectory for
          # executable compiler scratch instead.
          TMPDIR = "/run/hellas";
          XDG_CACHE_HOME = "/var/cache/hellas";
        }
        // lib.optionalAttrs providerGpuConfigured gpuEnvironment
      );
      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [ "${cfg.package}/bin/hellas" ]
          ++ hellas.mkServeArgs {
            inherit lib;
            serve = cfg;
          }
        );
        Restart = "on-failure";
        DynamicUser = true;
        RuntimeDirectory = "hellas";
        RuntimeDirectoryMode = "0700";
        StateDirectory = "hellas";
        StateDirectoryMode = "0700";
        CacheDirectory = "hellas";
        CacheDirectoryMode = "0700";
        WorkingDirectory = hellasLib.defaultStateDir;
        UMask = "0077";
        # Keep memory exhaustion inside this unit. OOMPolicy=kill sets
        # memory.oom.group=1, so a child OOM cannot leave a half-alive parent.
        MemorySwapMax = 0;
        OOMPolicy = "kill";
      }
      // lib.optionalAttrs (providerWritablePaths != [ ]) {
        # DynamicUser implies ProtectSystem=strict. Permit only the dedicated
        # external publication boundaries. These mount-namespace rules do not
        # grant Unix ownership, so operators must provision the external paths
        # as described by the corresponding options.
        ReadWritePaths = providerWritablePaths;
      }
      // lib.optionalAttrs (providerContentPaths != [ ]) {
        # Content is adopted as input, never service-owned state. Keep it
        # read-only even when an operator places it below StateDirectory,
        # CacheDirectory, or a broader custom writable mount.
        ReadOnlyPaths = providerContentPaths;
      }
      // lib.optionalAttrs (cfg.memoryMaxBytes != null) {
        MemoryMax = toString cfg.memoryMaxBytes;
      }
      // lib.optionalAttrs (cfg.environmentFile != null) {
        EnvironmentFile = cfg.environmentFile;
      }
      // lib.optionalAttrs providerGpuConfigured (
        gpuDeviceAccess
        // {
          # The shared VRAM owner uploads weights once; execution workers keep
          # mutable generation state private. GPU runtimes may still lock host
          # pages for upload staging and driver queues. RLIMIT_MEMLOCK permits
          # those operations; asset admission and MemoryMax remain separate.
          LimitMEMLOCK = "infinity";
        }
      );
    };

    systemd.services.hellas-gateway = mkIf gateway.enable {
      description = "Hellas HTTP gateway";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      unitConfig = lib.optionalAttrs (gatewayRuntimePaths != [ ]) {
        RequiresMountsFor = gatewayRuntimePaths;
      };
      environment = hellas.renderEnvironment (
        hellas.mkOtelEnv {
          inherit lib;
          inherit (cfg) otel;
        }
        // cfg.environment
        // {
          HOME = "/var/lib/hellas-gateway";
        }
        // lib.optionalAttrs cfg.otel.enable {
          # Distinguish gateway spans from the node's in shared trace storage.
          OTEL_SERVICE_NAME = "${cfg.otel.serviceName}-gateway";
        }
      );
      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [ "${gateway.package}/bin/hellas" ]
          ++ hellas.mkGatewayArgs {
            inherit lib gateway;
          }
        );
        Restart = "on-failure";
        DynamicUser = true;
        StateDirectory = "hellas-gateway";
        StateDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/hellas-gateway";
        UMask = "0077";
      }
      // lib.optionalAttrs (gatewayWritablePaths != [ ]) {
        ReadWritePaths = gatewayWritablePaths;
      }
      // lib.optionalAttrs (gateway.environmentFile != null) {
        EnvironmentFile = gateway.environmentFile;
      };
    };

    networking.firewall = {
      allowedUDPPorts = lib.optionals (cfg.enable && cfg.openFirewall && cfg.port != null) [ cfg.port ];
      allowedTCPPorts = lib.optionals (gateway.enable && gateway.openFirewall && gateway.port != null) [
        gateway.port
      ];
    };
  };
}
