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
  inherit (lib)
    mkEnableOption
    mkIf
    mkMerge
    mkOption
    optionals
    types
    ;
  cfg = config.programs.hellas;
  inherit (pkgs.stdenv.hostPlatform) isDarwin;
  outsideStorePath = hellas.runtimePathIsOutsideStore lib;
  outsideStoreString = hellas.runtimeStringIsOutsideStore lib;
  userEnvironmentStrings = lib.filter builtins.isString (lib.attrValues cfg.environment);
  serveRuntimePaths = [
    cfg.serve.identityPath
  ]
  ++ cfg.serve.content
  ++ cfg.serve.contentRoots
  ++ lib.optional (cfg.serve.contentIndex != null) cfg.serve.contentIndex
  ++ lib.optional (cfg.serve.artifactStorePath != null) cfg.serve.artifactStorePath
  ++ lib.optional (cfg.serve.workConfigFile != null) cfg.serve.workConfigFile
  ++ lib.optional (cfg.serve.fetchConfigFile != null) cfg.serve.fetchConfigFile
  ++ lib.optional (cfg.serve.environmentFile != null) cfg.serve.environmentFile;

  baseEnv =
    hellas.mkOtelEnv {
      inherit lib;
      inherit (cfg) otel;
    }
    // cfg.environment;
  serveCommand = [
    "${cfg.package}/bin/hellas-cli"
  ]
  ++ hellas.mkServeArgs {
    inherit lib;
    inherit (cfg) serve;
  };
  serveProgramArguments =
    if cfg.serve.environmentFile == null then
      serveCommand
    else
      [
        "${hellas.mkRuntimeEnvironmentWrapper pkgs}"
        cfg.serve.environmentFile
      ]
      ++ serveCommand;
in
{
  options.programs.hellas =
    hellas.commonOptions {
      inherit lib;
      package = (hellas.pickCliPackage pkgs).override { otel = cfg.otel.enable; };
      inherit (cfg) otel;
      packageDescription = ''
        The hellas network CLI, including chain, gateway and node support. The shared
        `otel` options select a telemetry-enabled build when configured. On x86_64-linux, overriding `programs.hellas.package` with
        this flake's `cli-catena` package enables interactive local Catena
        commands only. A Linux Catena provider daemon requires the NixOS
        `services.hellas` module; the Home Manager daemon is Darwin-only and
        network-only.
      '';
    }
    // {
      # User-space serve daemon. Currently darwin-only (uses HM's launchd
      # integration). Linux users should use the NixOS module instead.
      serve = {
        enable = mkEnableOption "Hellas serve daemon as a launchd user agent (darwin only)";
        environmentFile = mkOption {
          type = types.nullOr (types.strMatching "/.*");
          default = null;
          example = "/Users/alice/.config/hellas/provider.env";
          description = ''
            Absolute path to a trusted runtime environment file for provider
            secrets. launchd records this path, but the file contents are read
            only when the agent starts and never enter the Nix store or plist.

            Pass only the path as a plain string. Never interpolate a Nix path,
            package, derivation, or builtins.readFile result here: evaluation
            would copy or read the secret before this module or its runtime
            wrapper could validate it.

            Each nonempty, non-comment line must be NAME=VALUE, where NAME
            matches [A-Za-z_][A-Za-z0-9_]*. A comment starts with # in column
            one. VALUE is used literally: spaces, #, and = are preserved, with
            no quoting, escapes, interpolation, or command substitution.
            Duplicate names, CR/NUL bytes, malformed lines, a missing file, or
            a non-regular/unreadable file make the agent fail before Hellas is
            executed. Parent symlinks are resolved, the final component may
            not be a symlink, and the resolved path may not enter the Nix
            store. The opened file must be regular, owned by the agent's
            effective user, and grant no permissions to group or other users.
          '';
        };
      }
      // hellas.serveOptions { inherit lib pkgs; };
    };

  config = mkMerge [
    {
      # The shared serve option defaults to the NixOS StateDirectory. Preserve
      # the CLI's HOME-relative identity for the Darwin user daemon.
      programs.hellas.serve.identityPath = lib.mkDefault "${config.home.homeDirectory}/.hellas/identity";
    }

    (mkIf cfg.enable {
      home.packages = [
        (hellas.withEnvironment {
          inherit lib pkgs;
          inherit (cfg) package;
          environment = baseEnv;
        })
      ];
    })

    # Surface a clear assertion on Linux rather than a "no such option" error
    # when the user enables `programs.hellas.serve` on the wrong platform.
    (mkIf cfg.serve.enable {
      assertions =
        optionals (!isDarwin) [
          {
            assertion = false;
            message = ''
              programs.hellas.serve is only supported on darwin (HM launchd).
              On Linux, use the NixOS module `services.hellas` instead.
            '';
          }
        ]
        ++ optionals isDarwin [
          {
            assertion = !hellas.catenaConfigured cfg.serve;
            message = "Local Catena execution is not supported by the Darwin Home Manager daemon.";
          }
        ];
    })

    (mkIf (cfg.enable || cfg.serve.enable) {
      assertions = [
        {
          assertion = hellas.extraArgsAreSafe lib hellas.protectedServeExtraArgs cfg.serve.extraArgs;
          message = "programs.hellas.serve.extraArgs may not override module-managed runtime, content, identity, trust, or configuration flags; use the corresponding option instead.";
        }
        {
          assertion = lib.all outsideStoreString userEnvironmentStrings;
          message = "programs.hellas.environment string values must not use file: URIs or point into the Nix store; use runtime paths or programs.hellas.serve.environmentFile for runtime data and secrets.";
        }
      ];
    })

    (mkIf cfg.serve.enable {
      assertions = [
        {
          assertion = lib.all outsideStorePath serveRuntimePaths;
          message = "programs.hellas.serve content, identity, artifact store, environment, work config, Fetch config, and environment-file paths must be runtime data outside the Nix store.";
        }
      ];
    })

    (mkIf (cfg.serve.enable && isDarwin) {
      launchd.agents.hellas = {
        enable = true;
        config = {
          ProgramArguments = serveProgramArguments;
          RunAtLoad = true;
          KeepAlive = true;
          EnvironmentVariables = hellas.renderEnvironment (baseEnv // { HOME = config.home.homeDirectory; });
          StandardOutPath = "${config.home.homeDirectory}/Library/Logs/hellas/stdout.log";
          StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/hellas/stderr.log";
        };
      };
    })
  ];
}
