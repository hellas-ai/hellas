{ self }:
rec {
  # The ordinary CLI omits OTEL. Modules opt in through the package override.
  # It carries the network, chain and gateway surfaces. Local Catena execution is the explicit `cli-catena` package.
  normalCliPackage = pkgs: self.packages.${pkgs.stdenv.hostPlatform.system}.cli;
  catenaPlatform = pkgs: pkgs.stdenv.hostPlatform.system == "x86_64-linux";
  catenaCliPackage = pkgs: self.packages.${pkgs.stdenv.hostPlatform.system}.cli-catena;
  nixosCliPackage =
    pkgs: if catenaPlatform pkgs then catenaCliPackage pkgs else normalCliPackage pkgs;

  pickCliPackage = normalCliPackage;

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
          wrapProgram "$out/bin/hellas-cli" ${
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

  executionEnvironmentGlobIsValid =
    pattern: builtins.isString pattern && builtins.match "[0-9a-f*]{1,64}" pattern != null;

  executePolicyIsValid =
    policy:
    policy == null
    || (
      if builtins.isString policy then
        policy == "any"
        || policy == "none"
        || builtins.match "only\\([0-9a-f*]{1,64}(,[0-9a-f*]{1,64})*\\)" policy != null
      else
        builtins.isList policy && policy != [ ] && builtins.all executionEnvironmentGlobIsValid policy
    );

  executePolicyEnablesCatena =
    policy: executePolicyIsValid policy && policy != null && policy != "none";

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
    "--execute-policy"
    "--queue-size"
    "--content"
    "--content-root"
    "--content-index"
    "--gpu-backend"
    "--gpu-session-programs"
    "--gpu-session-asset-bytes"
    "--gpu-max-generation-capacity"
    "--gpu-max-generation-device-bytes"
    "--gpu-compile-timeout-secs"
    "--gpu-execution-timeout-secs"
    "--evaluate-retained-execution-capacity"
    "--artifact-store-path"
    "--work-config"
    "--metrics-port"
    "--graffiti"
    "--fetch-config"
    "--fetch-max-in-flight"
    "--fetch-queue-size"
    "--fetch-retained-transcript-capacity"
    "--fetch-replay-max-in-flight"
  ];

  protectedGatewayExtraArgs = [
    "--paid-work-config"
    "--bearer-token-file"
    "--identity"
    "--log-file"
    "--assurance"
    "--environment"
    "--model"
    "--content"
    "--content-root"
    "--content-index"
    "--tokenizer"
    "--chat-template"
    "--stop-token"
    "--host"
    "--port"
    "--node-id"
    "--node-addr"
    "--local"
    "--verify-local"
    "--verify"
    "--provider"
    "--queue-size"
    "--retries"
    "--default-max-tokens"
    "--metrics-port"
    "--responses-backend"
    "--responses-proxy-url"
    "--responses-proxy-api-key-env"
    "--responses-fetch-route-service"
    "--responses-fetch-route-method"
    "--responses-fetch-execution-environment"
    "--responses-fetch-request-overrides"
    "--apple-app-attest-cdhashes"
    "--apple-app-attest-app-id"
  ];

  extraArgsAreSafe =
    lib: protected: args:
    lib.all (arg: lib.all (flag: arg != flag && !(lib.hasPrefix "${flag}=" arg)) protected) args;

  catenaConfigured =
    serve:
    executePolicyEnablesCatena serve.executePolicy
    || serve.content != [ ]
    || serve.contentRoots != [ ]
    || serve.contentIndex != null
    || serve.gpuBackend != null
    || serve.gpuSessionPrograms != null
    || serve.gpuSessionAssetBytes != null
    || serve.gpuMaxGenerationCapacity != null
    || serve.gpuMaxGenerationDeviceBytes != null
    || serve.gpuCompileTimeoutSeconds != null
    || serve.gpuExecutionTimeoutSeconds != null
    || serve.evaluateRetainedExecutionCapacity != null;

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
  # any other future daemon surface. The keys here mirror `hellas-cli serve`'s
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
      executePolicy = mkOption {
        type = types.addCheck (types.nullOr (types.either types.str (types.listOf types.str))) executePolicyIsValid;
        default = "none";
        example = [ "0123456789abcdef*" ];
        description = ''
          Catena evaluate policy. The default, "none", refuses all Evaluate
          executions without activating the local Catena/ROCm runtime. Set
          "any" explicitly to accept every supported environment for which the
          provider has all content, or use "only(ID_GLOB,...)" to restrict exact
          execution-environment content identities. Every glob must contain
          one to 64 lowercase hexadecimal digits or `*`; whitespace is not
          accepted. A nonempty list is shorthand for "only(p1,p2,...)".
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
      artifactStorePath = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        example = "/srv/hellas/artifacts";
        description = ''
          Persistent canonical artifact-store root passed as
          --artifact-store-path. Keep it as dedicated operator-managed runtime
          data outside the Nix store and outside content/contentRoots. With the
          NixOS DynamicUser unit, pre-create a custom root and grant write
          access through an id-mapped mount, or override the unit to use a
          dedicated static user that owns it. The service intentionally narrows
          the root to owner-only permissions, so group write access alone is
          insufficient; never chown persistent data to a transient numeric
          dynamic UID. Its path and ancestors must remain stable and trusted
          while the service runs.
          Null omits the flag and uses the securely managed CLI default,
          $HOME/.hellas/artifacts.
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
      gpuMaxGenerationCapacity = mkOption {
        type = types.nullOr (types.ints.between 1 524288);
        default = null;
        description = "Maximum prompt-plus-output token capacity admitted for one GPU generation (at most 524288, so retained output fits the artifact transport). Null uses the CLI default.";
      };
      gpuMaxGenerationDeviceBytes = positiveLimitOption "Maximum non-asset device bytes owned or allocated by one GPU generation, including resident state, token staging, outputs, and intermediates. Null uses the CLI default.";
      gpuCompileTimeoutSeconds = positiveLimitOption "Maximum seconds spent loading and compiling one Catena program. Null uses the CLI default.";
      gpuExecutionTimeoutSeconds = positiveLimitOption "Maximum seconds for one GPU control operation or complete generation. Null uses the CLI default.";
      workConfigFile = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        example = "/var/lib/hellas/work.json";
        description = ''
          Runtime paid-work configuration passed as --work-config. A paid
          provider reads an existing identity rather than creating one, so
          initialize its identity before enabling this option. Keep the file
          and every journal path it names outside the Nix store.
        '';
      };
      fetchConfigFile = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        example = "/run/secrets/hellas-fetch.json";
        description = ''
          Runtime JSON file containing sealed Fetch destinations, credential
          references, capabilities, and caller policy. Passed as
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
      fetchRetainedTranscriptCapacity = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = ''
          Maximum distinct retained Fetch inputs across completed transcripts
          and indeterminate running markers. Zero disables new retention. The
          value is persisted per transcript-store root; stop every process
          sharing that root before changing it or removing the capacity
          metadata. Existing evidence is never deleted, and an over-cap root
          still starts and replays but refuses new retention. Null uses the CLI
          default of 1024.
        '';
      };
      fetchReplayMaxInFlight = mkOption {
        type = types.nullOr types.ints.positive;
        default = null;
        description = "Maximum retained Fetch replays whose consumers have not drained or dropped their streams. Null uses the CLI default of 16.";
      };
      evaluateRetainedExecutionCapacity = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = ''
          Maximum distinct retained Evaluate executions. Zero disables new
          retained completions. The value is persisted with the Evaluate
          artifact-store root, which one provider process owns exclusively;
          stop it before changing this value or removing its metadata. Null
          uses the CLI default of 1024.
        '';
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
        description = "Extra arguments to pass to `hellas-cli serve`. They may add unsupported harmless switches such as `--software-root`, but may not override module-managed runtime, content, identity, trust, or configuration flags (including `--flag=value`).";
      };
    };

  gatewayOptions =
    { lib }:
    let
      inherit (lib) mkEnableOption mkOption types;
      runtimePath = types.strMatching "/.*";
      u32 = types.ints.between 0 4294967295;
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
      allowRemote = mkEnableOption "non-loopback gateway listening (requires bearerTokenFile)";
      bearerTokenFile = mkOption {
        type = types.nullOr runtimePath;
        default = null;
        example = "/var/lib/hellas-gateway/bearer-token";
        description = "Private bearer credential file. Created on first startup and reused across restarts; never logged.";
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
      nodeId = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Direct target node id. Null enables discovery unless local mode is selected.";
      };
      nodeAddrs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Direct UDP address hints for the target node.";
      };
      local = mkOption {
        type = types.bool;
        default = false;
        description = "Run the gateway against an in-process Catena executor.";
      };
      verifyLocal = mkOption {
        type = types.bool;
        default = false;
        description = "Verify remote responses against an in-process Catena executor.";
      };
      verifyNodeId = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Remote node id used as the verification shadow.";
      };
      provider = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Out-of-band ContentId pin on the enrollment bundle of the provider this gateway dials. Required whenever it dials one: with nodeId, verifyNodeId, or responsesBackend = \"fetch\".";
      };
      queueSize = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = "Maximum number of queued local executions. Zero admits no waiting executions.";
      };
      retries = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = "Maximum execution retries in discovery mode.";
      };
      defaultMaxTokens = mkOption {
        type = types.nullOr positiveU32;
        default = null;
        description = "Fallback max output tokens when a request omits a limit.";
      };
      causalLmEnvironment = mkOption {
        type = types.strMatching "/.*";
        example = "/srv/hellas/environments/smollm2.environment";
        description = ''
          Canonical causal-LM environment file passed as --environment. Its
          exact bytes determine the manifest sent to providers. This is
          operator-managed runtime data, not a Nix-store artifact.
          responsesBackend changes only /v1/responses; the gateway's other
          routes continue to use this environment.
        '';
      };
      model = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional presentation-only model label returned by HTTP APIs; null uses the manifest ID. It does not enter the execution claim.";
      };
      content = mkOption {
        type = types.listOf (types.strMatching "/.*");
        default = [ ];
        example = [ "/srv/hellas/content/model.hex" ];
        description = "Local content files used only by local execution or verification. Passed as repeatable --content arguments.";
      };
      contentRoots = mkOption {
        type = types.listOf (types.strMatching "/.*");
        default = [ ];
        example = [ "/srv/hellas/content" ];
        description = "Local content trees used only by local execution or verification. Passed as repeatable --content-root arguments.";
      };
      contentIndex = mkOption {
        type = types.nullOr (types.strMatching "/.*");
        default = null;
        description = ''
          Fast-resume index for local content. Null uses the CLI's persistent
          HOME-relative store state. Valid only with local execution or local
          verification. Atomic publication needs a writable sibling, so a
          custom NixOS path must have a dedicated parent outside content and
          contentRoots. Pre-create it and grant the DynamicUser unit write
          access through an id-mapped mount, or override the unit to use a
          dedicated static user that owns it. A group-writable parent alone is
          insufficient because index files are owner-only. Never chown
          persistent data to a transient numeric dynamic UID. Keep the path and
          its ancestors stable and trusted while the service runs.
        '';
      };
      tokenizer = mkOption {
        type = types.strMatching "/.*";
        example = "/srv/hellas-presentation/smollm2-tokenizer.json";
        description = ''
          Application-selected tokenizer JSON. This presentation input is
          independent of the Catena execution environment and is not covered by
          the Hellas execution guarantee.
        '';
      };
      chatTemplate = mkOption {
        type = types.nullOr (
          types.enum [
            "qwen3"
            "qwen3.5"
            "qwen3.6"
            "smollm2"
          ]
        );
        default = null;
        description = "Shared text-chat model adapter with thinking disabled and tool-call support. Qwen3 uses JSON tool calls; Qwen3.5 and Qwen3.6 use XML function calls. Null supports plain completions only. Multimodal messages are unsupported.";
      };
      stopTokenIds = mkOption {
        type = types.listOf u32;
        default = [ ];
        example = [ 2 ];
        description = "Caller-selected stop token IDs; none are inferred from the tokenizer or Catena environment.";
      };
      metricsPort = mkOption {
        type = types.nullOr types.port;
        default = null;
        description = "Optional loopback-only Prometheus metrics port.";
      };
      responsesBackend = mkOption {
        type = types.enum [
          "hellas"
          "proxy"
          "fetch"
        ];
        default = "hellas";
        description = "Backend used only by /v1/responses. Other gateway routes remain causal-LM.";
      };
      responsesProxyUrl = mkOption {
        type = types.str;
        default = "https://api.openai.com/v1/responses";
        description = "Upstream endpoint used when responsesBackend is proxy.";
      };
      responsesProxyApiKeyEnv = mkOption {
        type = types.str;
        default = "OPENAI_API_KEY";
        description = "Environment variable containing the Responses proxy bearer token.";
      };
      responsesFetchRouteService = mkOption {
        type = types.str;
        default = "codex";
        description = "Fetch route service used when responsesBackend is fetch.";
      };
      responsesFetchRouteMethod = mkOption {
        type = types.str;
        default = "responses";
        description = "Fetch route method used when responsesBackend is fetch.";
      };
      responsesFetchExecutionEnvironment = mkOption {
        type = types.nullOr (types.strMatching "(codex-responses|openai-responses|[0-9a-f]{64})");
        default = null;
        description = ''
          Built-in Fetch environment alias ("codex-responses" or
          "openai-responses") or exact ProgramManifest identity expected from
          the selected provider route.
        '';
      };
      responsesFetchRequestOverrides = mkOption {
        type = types.attrsOf types.anything;
        default = { };
        description = "JSON object merged into OpenAI Responses requests before signing and sending them through Fetch.";
      };
      assurance = mkOption {
        type = types.enum [
          "producer-signed"
          "apple-app-attest"
        ];
        default = "producer-signed";
        description = "Assurance requested from the selected execution provider.";
      };
      appleAppAttestCdhashes = mkOption {
        type = types.listOf (types.strMatching "[0-9A-Fa-f]{64}");
        default = [ ];
        description = "Allowed Apple App Attest application CDhashes for remote confidential open. Required with apple-app-attest assurance.";
      };
      appleAppAttestAppId = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "TEAMID.example.hellas";
        description = "Apple App Attest application identity in teamID.bundleID form. Required with apple-app-attest assurance.";
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
        description = "Extra arguments to pass to `hellas-cli gateway`. They may add unsupported harmless switches such as `--wrap`, but may not override module-managed runtime, content, identity, trust, or configuration flags (including `--flag=value`).";
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

  # `hellas-cli serve ...` argv from a resolved serve cfg. The cfg shape is
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
      renderPolicy =
        value:
        if value == null then
          null
        else if lib.isList value then
          "only(${lib.concatStringsSep "," value})"
        else
          value;
    in
    [
      "serve"
      "--identity"
      serve.identityPath
    ]
    ++ optArg "--port" serve.port
    ++ optArg "--execute-policy" (renderPolicy serve.executePolicy)
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
    ++ optArg "--gpu-max-generation-capacity" serve.gpuMaxGenerationCapacity
    ++ optArg "--gpu-max-generation-device-bytes" serve.gpuMaxGenerationDeviceBytes
    ++ optArg "--gpu-compile-timeout-secs" serve.gpuCompileTimeoutSeconds
    ++ optArg "--gpu-execution-timeout-secs" serve.gpuExecutionTimeoutSeconds
    ++ optArg "--artifact-store-path" serve.artifactStorePath
    ++ optArg "--work-config" serve.workConfigFile
    ++ optArg "--metrics-port" serve.metricsPort
    ++ [
      "--assurance"
      serve.assurance
    ]
    ++ optArg "--graffiti" serve.graffiti
    ++ optArg "--fetch-config" serve.fetchConfigFile
    ++ optArg "--fetch-max-in-flight" serve.fetchMaxInFlight
    ++ optArg "--fetch-queue-size" serve.fetchQueueSize
    ++ optArg "--fetch-retained-transcript-capacity" serve.fetchRetainedTranscriptCapacity
    ++ optArg "--fetch-replay-max-in-flight" serve.fetchReplayMaxInFlight
    ++ optArg "--evaluate-retained-execution-capacity" serve.evaluateRetainedExecutionCapacity
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
    ++ lib.concatMap (cdhash: [
      "--apple-app-attest-cdhashes"
      cdhash
    ]) gateway.appleAppAttestCdhashes
    ++ optArg "--apple-app-attest-app-id" gateway.appleAppAttestAppId
    ++ [
      "--environment"
      gateway.causalLmEnvironment
      "--tokenizer"
      gateway.tokenizer
    ]
    ++ optArg "--model" gateway.model
    ++ optArg "--paid-work-config" gateway.paidWorkConfig
    ++ lib.optional gateway.allowRemote "--allow-remote"
    ++ optArg "--bearer-token-file" gateway.bearerTokenFile
    ++ optArg "--chat-template" gateway.chatTemplate
    ++ [
      "--host"
      gateway.host
    ]
    ++ optArg "--port" gateway.port
    ++ optArg "--node-id" gateway.nodeId
    ++ lib.concatMap (addr: [
      "--node-addr"
      addr
    ]) gateway.nodeAddrs
    ++ lib.optionals gateway.local [ "--local" ]
    ++ lib.optionals gateway.verifyLocal [ "--verify-local" ]
    ++ optArg "--verify" gateway.verifyNodeId
    ++ optArg "--provider" gateway.provider
    ++ optArg "--queue-size" gateway.queueSize
    ++ optArg "--retries" gateway.retries
    ++ optArg "--default-max-tokens" gateway.defaultMaxTokens
    ++ lib.concatMap (path: [
      "--content"
      path
    ]) gateway.content
    ++ lib.concatMap (path: [
      "--content-root"
      path
    ]) gateway.contentRoots
    ++ optArg "--content-index" gateway.contentIndex
    ++ lib.concatMap (token: [
      "--stop-token"
      (toString token)
    ]) gateway.stopTokenIds
    ++ optArg "--metrics-port" gateway.metricsPort
    ++ [
      "--responses-backend"
      gateway.responsesBackend
      "--responses-proxy-url"
      gateway.responsesProxyUrl
      "--responses-proxy-api-key-env"
      gateway.responsesProxyApiKeyEnv
      "--responses-fetch-route-service"
      gateway.responsesFetchRouteService
      "--responses-fetch-route-method"
      gateway.responsesFetchRouteMethod
    ]
    ++ optArg "--responses-fetch-execution-environment" gateway.responsesFetchExecutionEnvironment
    ++ lib.optionals (gateway.responsesFetchRequestOverrides != { }) [
      "--responses-fetch-request-overrides"
      (builtins.toJSON gateway.responsesFetchRequestOverrides)
    ]
    ++ gateway.extraArgs;
}
