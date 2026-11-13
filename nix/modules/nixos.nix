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
  hellasLib = import ../lib { inherit pkgs; };
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
  outsideManagedRoots = roots: path: !(lib.any (root: pathWithin root path) roots);
  providerWritablePaths = lib.optional (outsideManagedRoots [ hellasLib.defaultStateDir ] cfg.home) (
    normalizeRuntimePath cfg.home
  );
  gatewayContentPaths = lib.filter (lib.hasPrefix "/") (
    map (model: builtins.head (lib.splitString "@" model)) gateway.models
  );
  gatewayWritablePaths = lib.optional (!(pathWithin "/var/lib/hellas-gateway" gateway.home)) (
    normalizeRuntimePath gateway.home
  );
  providerGpuConfigured = hellas.catenaPlatform pkgs && cfg.enable;
  gatewayGpuConfigured =
    hellas.catenaPlatform pkgs && lib.any (model: !(lib.hasInfix "@" model)) gateway.models;
  inherit (hellasLib) cudaToolkit;
  rocmToolkit = hellasLib.mkRocmToolkit cfg.rocmPackages;
  nvidiaDriverEnabled = builtins.elem "nvidia" config.services.xserver.videoDrivers;
  useCuda = nvidiaDriverEnabled;
  useHip = !nvidiaDriverEnabled;
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
    cfg.home
  ]
  ++ lib.optional (cfg.chainConfig != null) cfg.chainConfig
  ++ lib.optional (cfg.passkey != null) cfg.passkey
  ++ lib.optional (cfg.environmentFile != null) cfg.environmentFile;
  gatewayRuntimePaths = lib.optionals gateway.enable (
    [ gateway.home ]
    ++ gatewayContentPaths
    ++ lib.mapAttrsToList (_: upstream: upstream.keyFile) gateway.upstreams
    ++ lib.optional (gateway.environmentFile != null) gateway.environmentFile
    ++ lib.optional (gateway.chainConfig != null) gateway.chainConfig
    ++ lib.optional (gateway.passkey != null) gateway.passkey
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
      rocmPackages = mkOption {
        type = types.raw;
        default = pkgs.rocmPackages;
        defaultText = lib.literalExpression "pkgs.rocmPackages";
        description = ''
          ROCm package set from which the HIP toolkit is assembled when the
          HIP backend is used. It must provide clang, clr, hip-common, hipcc,
          rocm-core, rocm-device-libs and rocm-runtime.
        '';
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
          unit. When set, it must exceed the native executor asset bound
          default (128 GiB) so the runtime, compiler,
          child workers, and non-asset allocations have headroom. The service
          never uses swap and an OOM kills the whole unit before
          Restart=on-failure restarts it.
        '';
      };
    };

  config = mkIf (cfg.enable || gateway.enable) {
    assertions = [
      {
        assertion = cfg.otel.enable || (cfg.metricsPort == null && gateway.metricsPort == null);
        message = "services.hellas metrics ports require otel.enable and packages built with the otel feature.";
      }
      {
        assertion = pkgs.stdenv.hostPlatform.isLinux;
        message = "services.hellas is only supported on Linux.";
      }
      {
        assertion = lib.all outsideStorePath (providerRuntimePaths ++ gatewayRuntimePaths);
        message = "services.hellas home, identity, key files, environment and model paths must be runtime data outside the Nix store.";
      }
      {
        assertion = lib.all outsideStoreString userEnvironmentStrings;
        message = "services.hellas.environment string values must not use file: URIs or point into the Nix store; use runtime paths or an EnvironmentFile for provider and gateway runtime data.";
      }
      {
        assertion = !cfg.enable || lib.all (path: path != "/") providerWritablePaths;
        message = "services.hellas.home must not expose the filesystem root as writable.";
      }
      {
        assertion = !gateway.enable || lib.all (path: path != "/") gatewayWritablePaths;
        message = "services.hellas.gateway writable journal paths must not expose the filesystem root as writable.";
      }
      {
        assertion = hellas.extraArgsAreSafe lib hellas.protectedServeExtraArgs cfg.extraArgs;
        message = "services.hellas.extraArgs may not override module-managed runtime, content, identity, trust, or configuration flags; use the corresponding option instead.";
      }
      {
        assertion = cfg.chain == null || cfg.chainConfig == null;
        message = "services.hellas.chain and chainConfig are mutually exclusive.";
      }
      {
        assertion = gateway.chain == null || gateway.chainConfig == null;
        message = "services.hellas.gateway.chain and chainConfig are mutually exclusive.";
      }
      {
        assertion = hellas.extraArgsAreSafe lib hellas.protectedGatewayExtraArgs gateway.extraArgs;
        message = "services.hellas.gateway.extraArgs may not override module-managed runtime, content, identity, trust, or configuration flags; use the corresponding option instead.";
      }
      {
        assertion = !gateway.enable || gateway.models != [ ];
        message = "services.hellas.gateway.models must name at least one model.";
      }
      {
        assertion = lib.all (model: lib.hasPrefix "/" model || lib.hasInfix "@" model) gateway.models;
        message = "services.hellas.gateway.models local packages must use absolute runtime paths.";
      }
      {
        assertion = !gateway.openFirewall || gateway.port != 0;
        message = "services.hellas.gateway.openFirewall requires a fixed port.";
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
            inherit (cfg) otel;
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
        # external home. These mount-namespace rules do not
        # grant Unix ownership, so operators must provision the external paths
        # as described by the corresponding options.
        ReadWritePaths = providerWritablePaths;
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
      path = lib.optionals gatewayGpuConfigured gpuPackages;
      environment = hellas.renderEnvironment (
        hellas.mkOtelEnv {
          inherit lib;
          inherit (cfg) otel;
        }
        // cfg.environment
        // {
          HOME = "/var/lib/hellas-gateway";
          TMPDIR = "/run/hellas-gateway";
          XDG_CACHE_HOME = "/var/cache/hellas-gateway";
        }
        // lib.optionalAttrs cfg.otel.enable {
          # Distinguish gateway spans from the node's in shared trace storage.
          OTEL_SERVICE_NAME = "${cfg.otel.serviceName}-gateway";
        }
        // lib.optionalAttrs gatewayGpuConfigured gpuEnvironment
      );
      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [ "${gateway.package}/bin/hellas" ]
          ++ hellas.mkGatewayArgs {
            inherit lib gateway;
            bearerFile = "/run/hellas-gateway/bearer";
            inherit (cfg) otel;
          }
        );
        Restart = "on-failure";
        DynamicUser = true;
        RuntimeDirectory = "hellas-gateway";
        RuntimeDirectoryMode = "0700";
        CacheDirectory = "hellas-gateway";
        CacheDirectoryMode = "0700";
        StateDirectory = "hellas-gateway";
        StateDirectoryMode = "0700";
        WorkingDirectory = "/var/lib/hellas-gateway";
        UMask = "0077";
      }
      // lib.optionalAttrs (gatewayWritablePaths != [ ]) {
        ReadWritePaths = gatewayWritablePaths;
      }
      // lib.optionalAttrs (gatewayContentPaths != [ ]) {
        ReadOnlyPaths = gatewayContentPaths;
      }
      // lib.optionalAttrs (gateway.environmentFile != null) {
        EnvironmentFile = gateway.environmentFile;
      }
      // lib.optionalAttrs gatewayGpuConfigured (
        gpuDeviceAccess
        // {
          # The in-process executor locks host pages for upload staging and
          # driver queues, exactly like the provider's native runtime.
          LimitMEMLOCK = "infinity";
        }
      );
    };

    networking.firewall = {
      allowedUDPPorts = lib.optionals (cfg.enable && cfg.openFirewall && cfg.port != null) [ cfg.port ];
      allowedTCPPorts = lib.optionals (gateway.enable && gateway.openFirewall && gateway.port != 0) [
        gateway.port
      ];
    };
  };
}
