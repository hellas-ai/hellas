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
  gatewayContentPaths = lib.unique (
    map normalizeRuntimePath (gateway.content ++ gateway.contentRoots)
  );
  providerWritablePaths = lib.unique (
    lib.optional (
      cfg.artifactStorePath != null
      && outsideManagedRoots providerManagedWritableRoots cfg.artifactStorePath
    ) (normalizeRuntimePath cfg.artifactStorePath)
    ++ lib.optional (
      cfg.contentIndex != null
      && outsideManagedRoots providerManagedWritableRoots (
        builtins.dirOf (normalizeRuntimePath cfg.contentIndex)
      )
    ) (builtins.dirOf (normalizeRuntimePath cfg.contentIndex))
  );
  gatewayWritablePaths = lib.unique (
    lib.optional (
      gateway.contentIndex != null
      && outsideManagedRoots gatewayManagedWritableRoots (
        builtins.dirOf (normalizeRuntimePath gateway.contentIndex)
      )
    ) (builtins.dirOf (normalizeRuntimePath gateway.contentIndex))
    ++ map normalizeRuntimePath gateway.paidWorkJournalRoots
    ++ lib.optional (
      gateway.bearerTokenFile != null
      && outsideManagedRoots gatewayManagedWritableRoots gateway.bearerTokenFile
    ) (builtins.dirOf (normalizeRuntimePath gateway.bearerTokenFile))
  );
  providerWritablePathsAreDisjoint = lib.all (
    writable: lib.all (content: !pathsOverlap writable content) providerContentPaths
  ) providerWritablePaths;
  gatewayWritablePathsAreDisjoint = lib.all (
    writable: lib.all (content: !pathsOverlap writable content) gatewayContentPaths
  ) gatewayWritablePaths;
  providerCatenaConfigured = hellas.catenaConfigured cfg || cfg.readinessEnvironments != [ ];
  providerLocalExecutionEnabled = hellas.executePolicyEnablesCatena cfg.executePolicy;
  providerGpuConfigured = hellas.catenaPlatform pkgs && providerLocalExecutionEnabled;
  defaultGpuSessionAssetBytes = 128 * 1024 * 1024 * 1024;
  effectiveGpuSessionAssetBytes =
    if cfg.gpuSessionAssetBytes == null then defaultGpuSessionAssetBytes else cfg.gpuSessionAssetBytes;
  inherit (hellasLib) rocmToolkit cudaToolkit;
  useHip = cfg.gpuBackend != "cuda";
  useCuda =
    cfg.gpuBackend == "cuda"
    || (cfg.gpuBackend != "hip" && builtins.elem "nvidia" config.services.xserver.videoDrivers);
  gpuPackages =
    lib.optionals useHip [ rocmToolkit ]
    ++ lib.optionals useCuda [
      cudaToolkit
      pkgs.cudaPackages.backendStdenv.cc
    ];
  gpuEnvironment =
    lib.optionalAttrs useHip (builtins.removeAttrs rocmEnvironment [ "LD_LIBRARY_PATH" ])
    // lib.optionalAttrs useCuda {
      CUDA_PATH = cudaToolkit;
      NVCC_CCBIN = "${pkgs.cudaPackages.backendStdenv.cc}/bin/c++";
    }
    // {
      LD_LIBRARY_PATH = lib.concatStringsSep ":" (
        lib.optional useHip "${rocmToolkit}/lib"
        ++ lib.optionals useCuda [
          "${cudaToolkit}/lib"
          "/run/opengl-driver/lib"
        ]
        ++ lib.optional (cfg.environment ? LD_LIBRARY_PATH) (toString cfg.environment.LD_LIBRARY_PATH)
      );
    };
  rocmEnvironment = {
    ROCM_PATH = rocmToolkit;
    HIP_PATH = rocmToolkit;
    HIP_CLANG_PATH = "${rocmToolkit}/bin";
    DEVICE_LIB_PATH = "${rocmToolkit}/amdgcn/bitcode";
    HIP_FLAGS = "--rocm-path=${rocmToolkit} --rocm-device-lib-path=${rocmToolkit}/amdgcn/bitcode";
    LD_LIBRARY_PATH =
      "${rocmToolkit}/lib"
      + lib.optionalString (
        cfg.environment ? LD_LIBRARY_PATH
      ) ":${toString cfg.environment.LD_LIBRARY_PATH}";
  };
  outsideStorePath = hellas.runtimePathIsOutsideStore lib;
  outsideStoreString = hellas.runtimeStringIsOutsideStore lib;
  userEnvironmentStrings = lib.filter builtins.isString (lib.attrValues cfg.environment);
  providerRuntimePaths = [
    cfg.identityPath
  ]
  ++ cfg.content
  ++ cfg.contentRoots
  ++ cfg.readinessEnvironments
  ++ lib.optional (cfg.contentIndex != null) cfg.contentIndex
  ++ lib.optional (cfg.artifactStorePath != null) cfg.artifactStorePath
  ++ lib.optional (cfg.workConfigFile != null) cfg.workConfigFile
  ++ lib.optional (cfg.fetchConfigFile != null) cfg.fetchConfigFile
  ++ lib.optional (cfg.environmentFile != null) cfg.environmentFile;
  gatewayRuntimePaths = lib.optionals gateway.enable (
    [
      gateway.causalLmEnvironment
      gateway.tokenizer
      gateway.identityPath
    ]
    ++ gateway.content
    ++ gateway.contentRoots
    ++ lib.optional (gateway.contentIndex != null) gateway.contentIndex
    ++ lib.optional (gateway.environmentFile != null) gateway.environmentFile
    ++ lib.optional (gateway.paidWorkConfig != null) gateway.paidWorkConfig
    ++ lib.optional (gateway.bearerTokenFile != null) gateway.bearerTokenFile
    ++ gateway.paidWorkJournalRoots
  );
  gpuDeviceAccess = {
    # DynamicUser does not inherit an interactive user's device groups.
    # The cgroup rule covers every DRM render node without baking a
    # device number into the module; /dev/kfd is ROCm's compute device.
    SupplementaryGroups = [
      "render"
      "video"
    ];
    DeviceAllow = [
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
  providerReadinessCommands = map (
    environment:
    lib.escapeShellArgs (
      [
        "${cfg.package}/bin/hellas-cli"
        "environment"
        "verify"
        "--environment"
        environment
      ]
      ++ lib.concatMap (path: [
        "--content"
        path
      ]) cfg.content
      ++ lib.concatMap (path: [
        "--content-root"
        path
      ]) cfg.contentRoots
      ++ lib.optionals (cfg.contentIndex != null) [
        "--content-index"
        cfg.contentIndex
      ]
    )
  ) cfg.readinessEnvironments;
in
{
  options.services.hellas =
    hellas.commonOptions {
      inherit lib;
      package = (hellas.nixosCliPackage pkgs).override { otel = cfg.otel.enable; };
      inherit (cfg) otel;
      packageDescription =
        if hellas.catenaPlatform pkgs then
          ''
            The hellas CLI used to run the serve daemon. On x86_64-linux it
            defaults to this flake's `cli-catena` package, which can compile
            and execute locally indexed Catena environments. Override
            `services.hellas.package` with the `cli` package for a network-only
            node.
          ''
        else
          ''
            The hellas network CLI used to run the serve daemon. Local Catena
            execution is currently available only on x86_64-linux because the
            packaged provider runtime currently targets that platform.
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
          description = ''
            The hellas CLI used to run the HTTP gateway. The default supports
            local Catena execution only on x86_64-linux; other platforms use
            the network-only CLI.
          '';
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
      readinessEnvironments = mkOption {
        type = types.listOf (types.strMatching "/.*");
        default = [ ];
        example = [ "/srv/hellas/content/smollm2.environment" ];
        description = ''
          Canonical causal-LM environments whose complete local content
          closures must verify before the provider starts. Each environment
          must also be discoverable through content or contentRoots; the path
          is not an implicit content source. This is a readiness baseline,
          never an execution allowlist: executePolicy still governs admission
          of every locally satisfiable environment. Routine startup trusts the
          persistent content index and does not re-hash unchanged large assets.
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
        assertion = pkgs.stdenv.hostPlatform.isLinux;
        message = "services.hellas is only supported on Linux.";
      }
      {
        assertion = !cfg.enable || cfg.assurance == "producer-signed";
        message = "services.hellas cannot serve apple-app-attest assurance on NixOS; Apple App Attest requires a Secure Enclave provider.";
      }
      {
        assertion = lib.all outsideStorePath (providerRuntimePaths ++ gatewayRuntimePaths);
        message = "services.hellas content, identity, artifact store, environment, work config, Fetch config, EnvironmentFile, and tokenizer paths must be runtime data outside the Nix store.";
      }
      {
        assertion = lib.all outsideStoreString userEnvironmentStrings;
        message = "services.hellas.environment string values must not use file: URIs or point into the Nix store; use runtime paths or an EnvironmentFile for provider and gateway runtime data.";
      }
      {
        assertion = !cfg.enable || lib.all (path: path != "/") providerWritablePaths;
        message = "services.hellas artifactStorePath and the parent of contentIndex must not expose the filesystem root as writable.";
      }
      {
        assertion = !gateway.enable || lib.all (path: path != "/") gatewayWritablePaths;
        message = "services.hellas.gateway contentIndex parent must not expose the filesystem root as writable.";
      }
      {
        assertion = !cfg.enable || providerWritablePathsAreDisjoint;
        message = "services.hellas external artifactStorePath and contentIndex parent must be dedicated writable locations outside content and contentRoots.";
      }
      {
        assertion = !gateway.enable || gatewayWritablePathsAreDisjoint;
        message = "services.hellas.gateway external contentIndex parent must be a dedicated writable location outside content and contentRoots.";
      }
      {
        assertion = cfg.readinessEnvironments == [ ] || cfg.content != [ ] || cfg.contentRoots != [ ];
        message = "services.hellas.readinessEnvironments requires services.hellas.content or contentRoots; an environment path is not an implicit content source.";
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
        assertion =
          hellas.catenaPlatform pkgs || (!providerCatenaConfigured && !gateway.local && !gateway.verifyLocal);
        message = "Local Catena execution is supported only on x86_64-linux; use executePolicy = \"none\" and omit content, contentRoots, contentIndex, GPU resource bounds, gateway.local, and gateway.verifyLocal on this platform.";
      }
      {
        assertion = gateway.nodeAddrs == [ ] || gateway.nodeId != null;
        message = "services.hellas.gateway.nodeAddrs requires services.hellas.gateway.nodeId.";
      }
      {
        assertion =
          !gateway.local
          || (gateway.nodeId == null && gateway.nodeAddrs == [ ] && gateway.verifyNodeId == null);
        message = "services.hellas.gateway.local cannot be combined with direct or verification node ids.";
      }
      {
        assertion = !(gateway.local && gateway.verifyLocal);
        message = "services.hellas.gateway.local and services.hellas.gateway.verifyLocal are mutually exclusive.";
      }
      {
        assertion = !(gateway.verifyLocal && gateway.verifyNodeId != null);
        message = "services.hellas.gateway.verifyLocal and services.hellas.gateway.verifyNodeId are mutually exclusive.";
      }
      {
        assertion =
          gateway.local || gateway.verifyLocal || (gateway.content == [ ] && gateway.contentRoots == [ ]);
        message = "services.hellas.gateway.content and contentRoots are only valid for local execution or local verification.";
      }
      {
        assertion = gateway.local || gateway.verifyLocal || gateway.contentIndex == null;
        message = "services.hellas.gateway.contentIndex is only valid for local execution or local verification.";
      }
      {
        assertion =
          !(gateway.local || gateway.verifyLocal) || gateway.content != [ ] || gateway.contentRoots != [ ];
        message = "services.hellas.gateway local execution and verification require content or contentRoots.";
      }
      {
        assertion = gateway.verifyNodeId == null || gateway.nodeId != null;
        message = "services.hellas.gateway.verifyNodeId requires services.hellas.gateway.nodeId.";
      }
      {
        assertion =
          !gateway.enable
          || gateway.provider != null
          || gateway.paidWorkConfig != null
          || gateway.local
          || (
            gateway.responsesBackend == "proxy"
            && !gateway.verifyLocal
            && gateway.nodeId == null
            && gateway.verifyNodeId == null
          );
        message = "services.hellas.gateway.provider is required by courtesy remote execution; a paid gateway uses its paidWorkConfig channel identities.";
      }
      {
        assertion =
          gateway.paidWorkConfig == null
          || (
            !gateway.local
            && !gateway.verifyLocal
            && gateway.verifyNodeId == null
            && gateway.nodeId == null
            && gateway.provider == null
            && gateway.responsesBackend == "hellas"
            && gateway.assurance == "producer-signed"
          );
        message = "services.hellas.gateway.paidWorkConfig requires remote producer-signed Hellas execution without courtesy target or verification overrides.";
      }
      {
        assertion =
          gateway.responsesBackend != "fetch" || gateway.responsesFetchExecutionEnvironment != null;
        message = "services.hellas.gateway.responsesFetchExecutionEnvironment is required when responsesBackend = \"fetch\".";
      }
      {
        assertion =
          !gateway.enable || (gateway.appleAppAttestAppId == null) == (gateway.appleAppAttestCdhashes == [ ]);
        message = "services.hellas.gateway.appleAppAttestAppId and appleAppAttestCdhashes must be configured together.";
      }
      {
        assertion =
          !gateway.enable || gateway.assurance != "apple-app-attest" || gateway.appleAppAttestAppId != null;
        message = "services.hellas.gateway apple-app-attest assurance requires appleAppAttestAppId and appleAppAttestCdhashes.";
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
          [ "${cfg.package}/bin/hellas-cli" ]
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
      // lib.optionalAttrs (providerReadinessCommands != [ ]) {
        # One argv-safe systemd command per baseline environment. Deliberately
        # omit --recheck on routine starts: the persistent index avoids hashing
        # tens of GiB again while verified opens still check exact identities.
        ExecStartPre = providerReadinessCommands;
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
      path = lib.optionals (gateway.local || gateway.verifyLocal) gpuPackages;
      environment = hellas.renderEnvironment (
        hellas.mkOtelEnv {
          inherit lib;
          inherit (cfg) otel;
        }
        // cfg.environment
        // {
          HOME = "/var/lib/hellas-gateway";
        }
        // lib.optionalAttrs (gateway.local || gateway.verifyLocal) (
          {
            # Local Catena execution dlopens generated shared objects, which
            # cannot live below DynamicUser's noexec CacheDirectory.
            TMPDIR = "/run/hellas-gateway";
            XDG_CACHE_HOME = "/var/cache/hellas-gateway";
          }
          // gpuEnvironment
        )
        // lib.optionalAttrs (cfg.otel.enable) {
          # Distinguish gateway spans from the node's in shared trace storage.
          OTEL_SERVICE_NAME = "${cfg.otel.serviceName}-gateway";
        }
      );
      serviceConfig = {
        ExecStart = lib.escapeShellArgs (
          [ "${gateway.package}/bin/hellas-cli" ]
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
        # The index uses atomic sibling publication, so only its dedicated
        # parent needs to be writable.
        ReadWritePaths = gatewayWritablePaths;
      }
      // lib.optionalAttrs (gatewayContentPaths != [ ]) {
        # Adopted content remains input even when it lives below one of the
        # unit's systemd-managed writable directories.
        ReadOnlyPaths = gatewayContentPaths;
      }
      // lib.optionalAttrs (gateway.local || gateway.verifyLocal) (
        {
          RuntimeDirectory = "hellas-gateway";
          RuntimeDirectoryMode = "0700";
          CacheDirectory = "hellas-gateway";
          CacheDirectoryMode = "0700";
        }
        // gpuDeviceAccess
        // {
          # Local gateways use the CLI's bounded default resident-asset limit.
          LimitMEMLOCK = "infinity";
        }
      )
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
