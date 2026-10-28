{ self }:
rec {
  # The ordinary CLI omits OTEL. Modules opt in through the package override.
  # It carries the network, chain, gateway and local Catena execution surfaces.
  normalCliPackage = pkgs: self.packages.${pkgs.stdenv.hostPlatform.system}.cli;
  catenaPlatform = pkgs: pkgs.stdenv.hostPlatform.system == "x86_64-linux";

  renderEnvironment = builtins.mapAttrs (_: toString);

  # Scope configuration to the ordinary CLI executable. In particular, an
  # OTLP endpoint for Hellas must not enable telemetry in every other program
  # launched by a Home Manager or Darwin login shell.
  withEnvironment =
    {
      lib,
      pkgs,
      package,
      environment,
    }:
    if environment == { } then
      package
    else
      pkgs.symlinkJoin {
        name = "hellas-configured";
        paths = [ package ];
        nativeBuildInputs = [ pkgs.makeWrapper ];
        postBuild = ''
          wrapProgram "$out/bin/hellas" ${
            lib.concatStringsSep " " (
              lib.mapAttrsToList (
                name: value: "--set-default ${lib.escapeShellArg name} ${lib.escapeShellArg (toString value)}"
              ) environment
            )
          }
        '';
        inherit (package) meta;
      };

  lexicallyNormalizeAbsolutePath =
    lib: path:
    let
      components = lib.foldl' (
        result: component:
        if component == "" || component == "." then
          result
        else if component == ".." then
          if result == [ ] then [ ] else lib.init result
        else
          result ++ [ component ]
      ) [ ] (lib.splitString "/" path);
    in
    "/${lib.concatStringsSep "/" components}";

  runtimePathIsOutsideStore =
    lib: path:
    builtins.isString path
    && !builtins.hasContext path
    && lib.hasPrefix "/" path
    && (
      let
        normalized = lexicallyNormalizeAbsolutePath lib path;
      in
      normalized != builtins.storeDir && !lib.hasPrefix "${builtins.storeDir}/" normalized
    );

  runtimeStringIsOutsideStore =
    lib: value:
    builtins.isString value
    && !builtins.hasContext value
    # Generic environment values are not parsed as URIs here. Reject file:
    # outright: normalization before percent-decoding cannot prove which local
    # path a downstream consumer will open. URL parsers may trim leading ASCII
    # whitespace and strip TAB/LF/CR inside a scheme, so control-bearing values
    # are refused and the probe is whitespace-trimmed before comparison.
    && builtins.match ".*[[:cntrl:]].*" value == null
    && !lib.hasPrefix "file:" (lib.toLower (lib.strings.trim value))
    && !lib.hasInfix "${builtins.storeDir}/" value
    && (!lib.hasPrefix "/" value || runtimePathIsOutsideStore lib value);

  # launchd has no EnvironmentFile equivalent. This generic executable reads
  # an operator-managed file only after launchd starts it; no value is captured
  # in the derivation. The target is opened exactly once, and parsing and exec
  # use Perl's list forms, so file contents are never interpreted by a shell.
  mkRuntimeEnvironmentWrapper =
    pkgs:
    let
      oCloexec =
        if pkgs.stdenv.hostPlatform.isDarwin then
          "0x01000000"
        else if pkgs.stdenv.hostPlatform.isLinux then
          "02000000"
        else
          throw "the Hellas runtime environment wrapper supports only Linux and Darwin";
    in
    pkgs.writers.writePerl "hellas-runtime-environment" { } ''
      use strict;
      use warnings;

      use Cwd qw(abs_path);
      use Fcntl qw(FD_CLOEXEC F_GETFD O_NOFOLLOW O_NONBLOCK O_RDONLY S_ISREG);
      use File::Basename qw(basename dirname);
      use File::Spec;

      sub fail {
          my ($message) = @_;
          print STDERR "hellas runtime environment: $message\n";
          exit 1;
      }

      @ARGV >= 2 or fail("expected ENVIRONMENT_FILE COMMAND [ARG ...]");
      my $environment_file = shift @ARGV;
      File::Spec->file_name_is_absolute($environment_file)
          or fail("'$environment_file' is not an absolute path");

      # Resolve only the parent before opening the target. This both avoids a
      # blocking pathname probe of a FIFO and makes parent-directory symlinks
      # visible to the Nix-store boundary. O_NOFOLLOW covers the final path
      # component, while the descriptor checks below govern the opened object.
      my $canonical_parent = abs_path(dirname($environment_file));
      defined($canonical_parent)
          or fail("cannot resolve the parent of '$environment_file': $!");
      my $canonical_environment_file =
          File::Spec->catfile($canonical_parent, basename($environment_file));
      my $canonical_store = abs_path(${builtins.toJSON builtins.storeDir});
      defined($canonical_store)
          or fail("cannot resolve the Nix store: $!");
      $canonical_environment_file ne $canonical_store
          && index($canonical_environment_file, "$canonical_store/") != 0
          or fail("'$environment_file' resolves into the Nix store");

      # Perl's Fcntl does not expose O_CLOEXEC on either supported family.
      # These are the native open(2) values from Linux and Darwin respectively.
      my $o_cloexec = ${oCloexec};
      sysopen(
          my $handle,
          $canonical_environment_file,
          O_RDONLY | O_NOFOLLOW | O_NONBLOCK | $o_cloexec
      ) or fail("cannot open '$environment_file': $!");
      binmode($handle, ":raw")
          or fail("cannot set raw mode on '$environment_file': $!");
      my $descriptor_flags = fcntl($handle, F_GETFD, 0);
      defined($descriptor_flags)
          or fail("cannot inspect descriptor flags for '$environment_file': $!");
      ($descriptor_flags & FD_CLOEXEC) != 0
          or fail("'$environment_file' was not opened close-on-exec");

      my @metadata = stat($handle);
      @metadata or fail("cannot inspect '$environment_file': $!");
      S_ISREG($metadata[2])
          or fail("'$environment_file' is not a regular file");
      $metadata[4] == $>
          or fail("'$environment_file' is not owned by the current effective user");
      ($metadata[2] & 0077) == 0
          or fail("'$environment_file' grants permissions to group or other users");

      my %seen;
      my $line_number = 0;
      while (defined(my $line = <$handle>)) {
          ++$line_number;
          $line =~ s/\n\z//;
          index($line, "\r") == -1
              or fail("$environment_file:$line_number: carriage returns are not permitted");
          index($line, "\0") == -1
              or fail("$environment_file:$line_number: NUL bytes are not permitted");

          next if $line eq "" || substr($line, 0, 1) eq "#";
          $line =~ /\A([A-Za-z_][A-Za-z0-9_]*)=(.*)\z/s
              or fail("$environment_file:$line_number: expected NAME=VALUE");
          my ($name, $value) = ($1, $2);
          !$seen{$name}
              or fail("$environment_file:$line_number: duplicate variable '$name'");
          $seen{$name} = 1;
          $ENV{$name} = $value;
      }
      close($handle) or fail("cannot close '$environment_file': $!");

      my $command = $ARGV[0];
      exec { $command } @ARGV or fail("cannot execute '$command': $!");
    '';

  # `extraArgs` is an escape hatch for CLI switches without a module option,
  # not a second, unchecked configuration surface. In particular, paths to
  # model content, credentials, and persistent state must go through the
  # typed runtime-path options that the platform modules verify stay outside
  # the store.
  protectedServeExtraArgs = [
    "--identity"
    "--log-file"
    "--assurance"
    "--port"
    "--queue-size"
    "--content"
    "--content-root"
    "--content-index"
    "--gpu-backend"
    "--gpu-session-programs"
    "--gpu-session-asset-bytes"
    "--paid-work-config"
    "--passkey"
    "--metrics-port"
    "--graffiti"
    "--fetch-config"
    "--fetch-max-in-flight"
    "--fetch-queue-size"
  ];

  protectedGatewayExtraArgs = [
    "--metrics-port"
    "--paid-work-config"
    "--gateway-profile"
    "--identity"
    "--log-file"
    "--assurance"
    "--text-model"
    "--host"
    "--port"
    "--default-max-tokens"
    "--responses-overrides"
    "--responses-model"
    "--trust-store"
    "--trust-policy"
    "--offer"
    "--passkey"
    "--work-profile"
    "--grant-policy"
  ];

  extraArgsAreSafe =
    lib: protected: args:
    lib.all (arg: lib.all (flag: arg != flag && !(lib.hasPrefix "${flag}=" arg)) protected) args;

  catenaConfigured =
    serve:
    serve.content != [ ]
    || serve.contentRoots != [ ]
    || serve.contentIndex != null
    || serve.gpuBackend != null
    || serve.gpuSessionPrograms != null
    || serve.gpuSessionAssetBytes != null;

  commonOptions =
    {
      lib,
      package,
      packageDescription,
      otel,
    }:
    let
      inherit (lib) mkEnableOption mkOption types;
    in
    {
      enable = mkEnableOption "Hellas";
      package = mkOption {
        type = types.package;
        default = package;
        description = packageDescription;
      };
      environment = mkOption {
        type = types.attrsOf (
          types.oneOf [
            types.str
            types.int
            types.bool
          ]
        );
        default = { };
        example = {
          RUST_LOG = "hellas=info";
          OTEL_SERVICE_NAME = "hellas";
        };
        description = "Non-secret scalar environment variables exported to Hellas processes. Paths and packages are rejected so Nix cannot copy runtime model data into the store; the platform modules additionally reject store-valued strings. Use a platform runtime environment-file mechanism for secrets.";
      };
      otel = otelOptions {
        inherit lib;
        cfg = otel;
      };
    };

  otelOptions =
    {
      lib,
      cfg,
      serviceName ? "hellas-node",
    }:
    let
      inherit (lib) mkOption types;
    in
    {
      enable = mkOption {
        type = types.bool;
        default = cfg.endpoint != null || cfg.collectorEndpoint != null;
        defaultText = lib.literalExpression "otel.endpoint != null || otel.collectorEndpoint != null";
        description = "Compile in OpenTelemetry and enable the configured exporters. Off when no endpoint is configured. The default package disables Hellas telemetry exporters.";
      };
      collectorEndpoint = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "http://localhost:4318";
        description = "OTEL_EXPORTER_OTLP_ENDPOINT — HTTP/protobuf collector base URL for traces and metrics. The SDK appends /v1/traces and /v1/metrics.";
      };
      endpoint = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "https://jaeger.example.com/v1/traces";
        description = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT — OTLP collector URL. Enables trace export when set.";
      };
      serviceName = mkOption {
        type = types.str;
        default = serviceName;
        description = "OTEL_SERVICE_NAME — service name attached to exported spans.";
      };
      sampleRate = mkOption {
        type = types.nullOr (types.numbers.between 0.0 1.0);
        default = null;
        example = 0.5;
        description = "OTEL_TRACES_SAMPLER_ARG — trace sample rate (0.0–1.0). Null uses the CLI default of 1.0.";
      };
      headers = mkOption {
        type = types.attrsOf types.str;
        default = { };
        example = {
          CF-Access-Client-Id = "abc123";
          Trace-Tenant = "production";
        };
        description = ''
          Non-secret OTEL_EXPORTER_OTLP_HEADERS entries sent with each export
          request. These values are rendered into Nix-managed process
          configuration. Put credentials in the platform runtime environment
          file as a complete OTEL_EXPORTER_OTLP_HEADERS value instead.
        '';
      };
    };

  # Serve-daemon options. Reused by NixOS systemd, HM-on-darwin launchd, and
  # any other future daemon surface. The keys here mirror `hellas serve`'s
  # CLI flags one-for-one — see `mkServeArgs` for the binding.
  serveOptions =
    { lib, pkgs }:
    let
      inherit (lib) mkOption types;
      hellasLib = import ../lib {
        inherit pkgs;
        inherit (self.inputs) nix-strix-halo;
      };
      runtimePath = types.strMatching "/.*";
      catenaMaxResidentAssetBytes = 4 * 1024 * 1024 * 1024 * 1024;
      positiveLimitOption =
        description:
        mkOption {
          type = types.nullOr types.ints.positive;
          default = null;
          inherit description;
        };
    in
    {
      port = mkOption {
        type = types.nullOr types.port;
        default = hellasLib.executorPort;
        description = "Port for the Hellas node to listen on. Null lets the CLI auto-select.";
      };
      identityPath = mkOption {
        type = runtimePath;
        default = "${hellasLib.defaultStateDir}/.hellas/identity";
        example = "/var/lib/hellas/.hellas/identity-v3";
        description = ''
          Versioned provider identity passed as --identity. This is the
          provider's persistent trust anchor, so select the existing identity
          explicitly when migrating from another filename. The file is
          operator-managed runtime data and must remain outside the Nix store.
        '';
      };
      queueSize = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = "Maximum number of queued executions waiting behind the active worker.";
      };
      content = mkOption {
        type = types.listOf runtimePath;
        default = [ ];
        example = [ "/srv/hellas/content/model.hex" ];
        description = ''
          Local files available to execution environments. Each path is
          indexed by content identity at startup and passed as --content.

          Values are strings, not Nix paths: model programs and assets remain
          operator-managed runtime data and must not be copied into the Nix
          store.
        '';
      };
      contentRoots = mkOption {
        type = types.listOf runtimePath;
        default = [ ];
        example = [ "/srv/hellas/content" ];
        description = ''
          Directory trees adopted into the local content store at startup,
          passed as repeatable --content-root arguments. No remote fetch is
          performed. Values are strings so their contents do not enter the
          Nix store.
        '';
      };
      contentIndex = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = ''
          Persistent fast-resume index for locally available content. Null
          uses the artifact-store default. Atomic publication writes a sibling
          temporary file, so a custom NixOS path must use a dedicated parent
          outside content and contentRoots. Pre-create that parent and grant
          durable ownership through an id-mapped mount, or override the unit to
          use a dedicated static user that owns it. A group-writable parent
          alone is insufficient because index files are owner-only. Never
          chown persistent data to a transient numeric dynamic UID. Keep the
          path and its ancestors stable and trusted while the service runs.
        '';
      };
      gpuBackend = mkOption {
        type = types.nullOr (
          types.enum [
            "auto"
            "hip"
            "cuda"
          ]
        );
        default = null;
        description = "GPU backend selected inside Catena's isolated worker. Null uses automatic detection.";
      };
      gpuSessionPrograms = positiveLimitOption "Maximum distinct Catena programs retained in one resident GPU session. Null uses the CLI default.";
      gpuSessionAssetBytes = mkOption {
        type = types.nullOr (types.ints.between 1 catenaMaxResidentAssetBytes);
        default = null;
        description = ''
          Logical admission limit for aggregate static bytes retained by the
          shared VRAM owner across execution-worker restarts (at most
          4398046511104 bytes, Catena's 4 TiB hard ceiling). Execution workers
          map these assets read-only and keep generation state private.
          Physical VRAM also includes allocation-granularity padding, private
          generation allocations, and driver overhead. Set memoryMaxBytes
          separately to bound host RAM. Null uses the CLI default.
        '';
      };
      workConfigFile = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        example = "/var/lib/hellas/paid-work.toml";
        description = ''
          Runtime TOML paid terms passed as --paid-work-config. The owner
          selected by passkey approves exactly these terms at startup; paid
          work is sold only with this file. Keep it outside the Nix store.
        '';
      };
      passkey = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = "Private software passkey of the provider's owner, passed as --passkey; required by workConfigFile unless extraArgs selects a faucet account.";
      };
      fetchConfigFile = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        example = "/run/secrets/hellas-fetch.json";
        description = ''
          Runtime JSON file containing sealed Fetch destinations, credential
          references and capabilities. Passed as
          --fetch-config without copying its contents into the Nix store.
          Null disables Fetch serving.
        '';
      };
      fetchMaxInFlight = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        description = "Maximum number of Fetch provider streams running at once.";
      };
      fetchQueueSize = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = "Maximum number of Fetch executions waiting behind active provider streams.";
      };
      metricsPort = mkOption {
        type = types.nullOr types.port;
        default = null;
        description = "Optional loopback-only Prometheus metrics port.";
      };
      assurance = mkOption {
        type = types.enum [
          "producer-signed"
          "apple-app-attest"
        ];
        default = "producer-signed";
        description = "Assurance requested from and served by the execution provider.";
      };
      graffiti = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Operator graffiti tag (up to 16 bytes, padded/truncated). Self-reported to peers.";
      };
      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Extra arguments to pass to `hellas serve`. They may add unsupported harmless switches such as `--software-root`, but may not override module-managed runtime, content, identity, trust, or configuration flags (including `--flag=value`).";
      };
    };

  gatewayOptions =
    { lib }:
    let
      inherit (lib) mkEnableOption mkOption types;
      runtimePath = types.strMatching "/.*";
      positiveU32 = types.ints.between 1 4294967295;
    in
    {
      enable = mkEnableOption "Hellas HTTP gateway";
      paidWorkConfig = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = "Runtime JSON provider pool for funded paid-work channels. Requests must match a configured provider's fixed generation policy; authenticated output is returned after payment acknowledgement.";
      };
      paidWorkJournalRoots = mkOption {
        type = types.listOf runtimePath;
        default = [ ];
        description = "Client journal directories named in paidWorkConfig, made writable in the service sandbox. Preserve these across restarts and provision ownership before starting the service.";
      };
      allowRemote = mkEnableOption "non-loopback gateway listening";
      gatewayProfile = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        example = "/var/lib/hellas-gateway/gateway-profile.json";
        description = "Private runtime profile selecting an explicitly provisioned HTTP authority, grant and gateway.invoke bearer credential. Startup never issues credentials.";
      };
      authorityJournal = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = "Authority journal named in gatewayProfile. Set this when it is outside the managed state directory so the service sandbox permits durable writes.";
      };
      host = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "Host interface for the HTTP gateway to bind.";
      };
      port = mkOption {
        type = types.nullOr types.port;
        default = 8080;
        description = "HTTP gateway port. Null lets the CLI auto-select.";
      };
      metricsPort = mkOption {
        type = types.nullOr types.port;
        default = null;
        description = "Optional loopback-only Prometheus metrics port.";
      };
      offer = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Previously imported allowance offer alias.";
      };
      passkey = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = "Private software passkey of the principal whose offer allowance execution uses.";
      };
      workProfile = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = "Provisioned private application credential and Work authorization profile.";
      };
      grantPolicy = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Select one granted resource by name.";
      };
      defaultMaxTokens = mkOption {
        type = types.nullOr positiveU32;
        default = null;
        description = "Fallback max output tokens when a request omits a limit.";
      };
      textModel = mkOption {
        type = types.nullOr (types.strMatching "/.*");
        default = null;
        example = "/srv/hellas/models/qwen3.gguf";
        description = ''
          GGUF passed as --text-model and served by the native text routes.
          Providers must already hold it. This is operator-managed runtime
          data, not a Nix-store artifact.
        '';
      };
      responsesOverrides = mkOption {
        type = types.attrsOf types.anything;
        default = { };
        description = "JSON object merged into OpenAI Responses requests before they are signed and sent as a Fetch.";
      };
      responsesModels = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Models the Responses Fetch answers to when /v1/responses is shared with the text routes.";
      };
      assurance = mkOption {
        type = types.enum [
          "producer-signed"
          "apple-app-attest"
        ];
        default = "producer-signed";
        description = "Assurance requested from the selected execution provider.";
      };
      trustStore = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = "Caller-owned native trust directory, provisioned separately by trust approve.";
      };
      trustPolicy = mkOption {
        type = types.nullOr (types.strMatching "[a-z0-9_-]{1,64}");
        default = null;
        description = "Previously approved enrollment, assurance, manifest and software policy ID.";
      };
      identityPath = mkOption {
        type = runtimePath;
        default = "/var/lib/hellas-gateway/.hellas/identity";
        description = "Versioned provider identity used by the HTTP gateway. This is operator-managed runtime state, not a Nix-store artifact.";
      };
      environmentFile = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        example = "/run/secrets/hellas-gateway.env";
        description = "Optional systemd EnvironmentFile path for gateway-only settings.";
      };
      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the HTTP gateway port in the firewall.";
      };
      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Extra arguments to pass to `hellas gateway`. They may add unsupported harmless switches such as `--wrap`, but may not override module-managed runtime, content, identity, trust, or configuration flags (including `--flag=value`).";
      };
    };

  # OTEL_EXPORTER_OTLP_* env vars derived from a resolved `otel` cfg.
  # Returns {} when no endpoint is set so callers can `//`-merge unconditionally.
  mkOtelEnv =
    {
      lib,
      otel,
    }:
    lib.optionalAttrs otel.enable (
      {
        OTEL_SERVICE_NAME = otel.serviceName;
      }
      // lib.optionalAttrs (otel.collectorEndpoint != null) {
        OTEL_EXPORTER_OTLP_ENDPOINT = otel.collectorEndpoint;
      }
      // lib.optionalAttrs (otel.endpoint != null) {
        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = otel.endpoint;
      }
      // lib.optionalAttrs (otel.sampleRate != null) {
        OTEL_TRACES_SAMPLER = "parentbased_traceidratio";
        OTEL_TRACES_SAMPLER_ARG = toString otel.sampleRate;
      }
      // lib.optionalAttrs (otel.headers != { }) {
        OTEL_EXPORTER_OTLP_HEADERS = lib.concatStringsSep "," (
          lib.mapAttrsToList (k: v: "${k}=${v}") otel.headers
        );
      }
    );

  # `hellas serve ...` argv from a resolved serve cfg. The cfg shape is
  # whatever attrset carries `serveOptions` keys — for NixOS that's the top-
  # level `services.hellas`, for HM-darwin it's `programs.hellas.serve`.
  mkServeArgs =
    {
      lib,
      serve,
    }:
    let
      optArg =
        flag: value:
        lib.optionals (value != null) [
          flag
          (toString value)
        ];
    in
    [
      "serve"
      "--identity"
      serve.identityPath
    ]
    ++ optArg "--port" serve.port
    ++ optArg "--queue-size" serve.queueSize
    ++ lib.concatMap (path: [
      "--content"
      path
    ]) serve.content
    ++ lib.concatMap (path: [
      "--content-root"
      path
    ]) serve.contentRoots
    ++ optArg "--content-index" serve.contentIndex
    ++ optArg "--gpu-backend" serve.gpuBackend
    ++ optArg "--gpu-session-programs" serve.gpuSessionPrograms
    ++ optArg "--gpu-session-asset-bytes" serve.gpuSessionAssetBytes
    ++ optArg "--paid-work-config" serve.workConfigFile
    ++ optArg "--passkey" serve.passkey
    ++ optArg "--metrics-port" serve.metricsPort
    ++ [
      "--assurance"
      serve.assurance
    ]
    ++ optArg "--graffiti" serve.graffiti
    ++ optArg "--fetch-config" serve.fetchConfigFile
    ++ optArg "--fetch-max-in-flight" serve.fetchMaxInFlight
    ++ optArg "--fetch-queue-size" serve.fetchQueueSize
    ++ serve.extraArgs;

  mkGatewayArgs =
    {
      lib,
      gateway,
    }:
    let
      optArg =
        flag: value:
        lib.optionals (value != null) [
          flag
          (toString value)
        ];
    in
    [
      "--identity"
      gateway.identityPath
      "gateway"
      "--assurance"
      gateway.assurance
    ]
    ++ optArg "--trust-store" gateway.trustStore
    ++ optArg "--trust-policy" gateway.trustPolicy
    ++ optArg "--offer" gateway.offer
    ++ optArg "--passkey" gateway.passkey
    ++ optArg "--work-profile" gateway.workProfile
    ++ optArg "--grant-policy" gateway.grantPolicy
    ++ optArg "--text-model" gateway.textModel
    ++ optArg "--paid-work-config" gateway.paidWorkConfig
    ++ lib.optional gateway.allowRemote "--allow-remote"
    ++ optArg "--gateway-profile" gateway.gatewayProfile
    ++ [
      "--host"
      gateway.host
    ]
    ++ optArg "--port" gateway.port
    ++ optArg "--metrics-port" gateway.metricsPort
    ++ optArg "--default-max-tokens" gateway.defaultMaxTokens
    ++ lib.optionals (gateway.responsesOverrides != { }) [
      "--responses-overrides"
      (builtins.toJSON gateway.responsesOverrides)
    ]
    ++ lib.optionals (gateway.responsesModels != [ ]) [
      "--responses-model"
      (lib.concatStringsSep "," gateway.responsesModels)
    ]
    ++ gateway.extraArgs;
}
