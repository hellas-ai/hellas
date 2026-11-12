{ self }:
rec {
  # A node runs local Catena Compute, so modules select the compute build.
  # It omits OTEL; modules opt in through the package override.
  normalCliPackage =
    pkgs: self.packages.${pkgs.stdenv.hostPlatform.system}.cli.override { compute = true; };
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
    "--durability"
    "--home"
    "--log-file"
    "--assurance"
    "--port"
    "--queue-size"
    "--content-config"
    "--gpu-backend"
    "--gpu-session-programs"
    "--gpu-session-asset-bytes"
    "--paid-work-config"
    "--chain"
    "--chain-config"
    "--grant-config"
    "--knowingly-unsafe"
    "--passkey"
    "--metrics-port"
    "--metrics-addr"
    "--graffiti"
    "--fetch-config"
    "--fetch-max-in-flight"
    "--fetch-queue-size"
  ];

  protectedGatewayExtraArgs = [
    "--content-config"
    "--metrics-port"
    "--metrics-addr"
    "--chain"
    "--chain-config"
    "--access"
    "--pay"
    "--provider"
    "--local"
    "--backend"
    "--model"
    "--gateway-profile"
    "--home"
    "--log-file"
    "--host"
    "--port"
    "--default-max-tokens"
    "--responses-overrides"
    "--responses-model"
    "--trust-store"
    "--trust-policy"
    "--passkey"
  ];

  extraArgsAreSafe =
    lib: protected: args:
    lib.all (arg: lib.all (flag: arg != flag && !(lib.hasPrefix "${flag}=" arg)) protected) args;

  catenaConfigured =
    serve:
    serve.gpuBackend != null || serve.gpuSessionPrograms != null || serve.gpuSessionAssetBytes != null;

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
        description = "Compile in metrics and OpenTelemetry export. Off when no endpoint is configured; set true explicitly for local metrics without OTLP. Custom packages must be built with the otel feature.";
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
      hellasLib = import ../lib { inherit pkgs; };
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
      home = mkOption {
        type = runtimePath;
        default = "${hellasLib.defaultStateDir}/.hellas";
        example = "/var/lib/hellas/.hellas";
        description = "Provider home passed as --home. Identity and all Hellas state live below this operator-managed directory.";
      };
      durability = mkOption {
        type = types.enum [
          "crash"
          "power"
        ];
        default = "crash";
        description = "Crash survives process crashes; OS crashes or power loss may roll back recent payment and authority commits with no time bound. Power flushes journal commits and content publication.";
      };
      queueSize = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = "Maximum number of queued executions waiting behind the active worker.";
      };
      content = mkOption {
        inherit (pkgs.formats.toml { }) type;
        default = { };
        example = {
          upper = "/var/lib/hellas/content-store";
          lower = [ "/srv/models" ];
          index = "resume";
        };
        description = ''
          The [content] declaration: upper, lower, index, capacity, pins and
          policy. Rendered as one TOML file passed through --content-config.
          An absent upper uses the store below home. Model bytes stay in
          runtime lower directories; use absolute string paths outside the
          Nix store. Pins default to Jobs.
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
      chain = mkOption {
        type = types.nullOr (types.enum [ "devnet" ]);
        default = null;
        description = "Compiled chain selection; null uses the binary default.";
      };
      chainConfig = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = "Authenticated custom chain profile passed as --chain-config.";
      };
      grantConfigFile = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        example = "/var/lib/hellas/grant.json";
        description = ''
          Runtime JSON grant resources and listener configuration passed as
          --grant-config. Native Compute runs through grants without paid
          work, so this file enables the same content and GPU service setup as
          workConfigFile. Keep it outside the Nix store.
        '';
      };
      knowinglyUnsafe = lib.mkEnableOption ''
        serving workConfigFile or grantConfigFile when it admits any Compute
        program (`mode = "any"`, or `Any` in a resource). Without this the node
        refuses to start on such a configuration: compiling and running a
        program from an unknown author hands that author roughly root on the
        host
      '';
      passkey = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = "Private software passkey of the provider's owner, passed as --passkey. Without it, workConfigFile uses the principal key in the provider's home, or an owner-approved policy.";
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
      metricsAddress = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "IP address for unauthenticated metrics. Non-loopback exposes them to the network.";
      };
      metricsPort = mkOption {
        type = types.nullOr types.port;
        default = null;
        description = "Optional unauthenticated Prometheus metrics port. Requires otel.enable and a package built with the otel feature.";
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
        description = "Extra arguments to pass to `hellas serve`. They may add harmless switches such as `--no-discovery`, but may not override module-managed runtime, content, identity, trust, or configuration flags (including `--flag=value`).";
      };
    };

  gatewayOptions =
    { lib, pkgs }:
    let
      inherit (lib) mkEnableOption mkOption types;
      runtimePath = types.strMatching "/.*";
      positiveU32 = types.ints.between 1 4294967295;
    in
    {
      enable = mkEnableOption "Hellas HTTP gateway";
      content = mkOption {
        inherit (pkgs.formats.toml { }) type;
        default = { };
        description = "The local [content] declaration, rendered as one --content-config file. An absent upper keeps the dedicated authority-local upper. Use runtime lower paths outside the Nix store.";
      };
      access = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        example = "/run/secrets/friend.access";
        description = "Access file someone shared with this gateway's principal and device, passed as --access. Requests run under its grant.";
      };
      pay = mkOption {
        type = types.nullOr positiveU32;
        default = null;
        description = "Most the gateway pays `provider` per request, passed as --pay. The provider's quoted price applies.";
      };
      provider = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "ENROLLMENT_ID@NODE_ID";
        description = "Paid provider address passed as --provider with pay.";
      };
      local = mkEnableOption "running requests on this machine's executor (--local), with the native content and GPU flags";
      backend = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "hellas/catena-dfad87438018-hip";
        description = "Renderer (evaluator id) that remote requests' programs are rendered for, passed as --backend: the id the provider's GPU runtime registers. Local requests render for this machine's GPU runtime.";
      };
      models = mkOption {
        type = types.listOf (types.strMatching "/.*");
        default = [ ];
        example = [ "/srv/hellas/models/qwen3.gguf" ];
        description = ''
          Model paths passed as --model: a Qwen GGUF file, or a converted
          Whisper or Flux package directory. The gateway renders jobs from
          them; providers must hold the same converted weights. This is
          operator-managed runtime data, not a Nix-store artifact.
        '';
      };
      chain = mkOption {
        type = types.nullOr (types.enum [ "devnet" ]);
        default = null;
        description = "Compiled chain selection; null uses the binary default.";
      };
      chainConfig = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = "Authenticated custom chain profile passed as --chain-config.";
      };
      allowRemote = mkEnableOption "non-loopback gateway listening";
      gatewayProfile = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        example = "/var/lib/hellas-gateway/gateway-profile.json";
        description = "Private runtime profile selecting an explicitly provisioned HTTP authority, grant and gateway.invoke bearer credential; required with allowRemote. Without it, a loopback gateway creates its own authority under home and keeps its bearer in home/gateway/bearer.";
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
      metricsAddress = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "IP address for unauthenticated metrics. Non-loopback exposes them to the network.";
      };
      metricsPort = mkOption {
        type = types.nullOr types.port;
        default = null;
        description = "Optional unauthenticated Prometheus metrics port. Requires otel.enable and a package built with the otel feature.";
      };
      passkey = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        description = "Private software passkey of the principal the gateway acts for, outside home.";
      };
      defaultMaxTokens = mkOption {
        type = types.nullOr positiveU32;
        default = null;
        description = "Fallback max output tokens when a request omits a limit.";
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
      home = mkOption {
        type = runtimePath;
        default = "/var/lib/hellas-gateway/.hellas";
        description = "Gateway home passed as --home. Identity, archives, counters and chain journals live below this directory.";
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
      pkgs,
      serve,
      otel,
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
      "--home"
      serve.home
    ]
    ++ [
      "--durability"
      serve.durability
    ]
    ++ optArg "--port" serve.port
    ++ optArg "--queue-size" serve.queueSize
    ++ lib.optionals (serve.content != { }) [
      "--content-config"
      ((pkgs.formats.toml { }).generate "hellas-content.toml" { inherit (serve) content; })
    ]
    ++ optArg "--gpu-backend" serve.gpuBackend
    ++ optArg "--gpu-session-programs" serve.gpuSessionPrograms
    ++ optArg "--gpu-session-asset-bytes" serve.gpuSessionAssetBytes
    ++ optArg "--paid-work-config" serve.workConfigFile
    ++ optArg "--chain" serve.chain
    ++ optArg "--chain-config" serve.chainConfig
    ++ optArg "--grant-config" serve.grantConfigFile
    ++ lib.optional serve.knowinglyUnsafe "--knowingly-unsafe"
    ++ optArg "--passkey" serve.passkey
    ++ lib.optionals (otel.enable && serve.metricsPort != null) [
      "--metrics-port"
      (toString serve.metricsPort)
      "--metrics-addr"
      serve.metricsAddress
    ]
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
      pkgs,
      gateway,
      otel,
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
      "--home"
      gateway.home
      "gateway"
    ]
    ++ lib.optionals (gateway.content != { }) [
      "--content-config"
      ((pkgs.formats.toml { }).generate "hellas-gateway-content.toml" { inherit (gateway) content; })
    ]
    ++ optArg "--trust-store" gateway.trustStore
    ++ optArg "--trust-policy" gateway.trustPolicy
    ++ optArg "--access" gateway.access
    ++ optArg "--pay" gateway.pay
    ++ optArg "--provider" gateway.provider
    ++ lib.optional gateway.local "--local"
    ++ optArg "--backend" gateway.backend
    ++ optArg "--passkey" gateway.passkey
    ++ lib.concatMap (model: [
      "--model"
      model
    ]) gateway.models
    ++ optArg "--chain" gateway.chain
    ++ optArg "--chain-config" gateway.chainConfig
    ++ lib.optional gateway.allowRemote "--allow-remote"
    ++ optArg "--gateway-profile" gateway.gatewayProfile
    ++ [
      "--host"
      gateway.host
    ]
    ++ optArg "--port" gateway.port
    ++ lib.optionals (otel.enable && gateway.metricsPort != null) [
      "--metrics-port"
      (toString gateway.metricsPort)
      "--metrics-addr"
      gateway.metricsAddress
    ]
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
