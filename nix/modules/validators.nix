{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    concatLists
    concatStringsSep
    escapeShellArg
    filterAttrs
    genList
    getExe
    literalExpression
    mapAttrsToList
    mkDefault
    mkEnableOption
    mkIf
    mkMerge
    mkOption
    optionalAttrs
    optionalString
    types
    ;

  cfg = config.services.hellas-chain-validators;
  hellas = import ./hellas.nix { inherit self; };

  localPorts = validator: basePort: genList (i: basePort + validator.nodeOffset + i) validator.nodes;

  lightClientBind =
    validator: index:
    let
      address = validator.lightClientRpc.bindAddress;
      host = if lib.hasInfix ":" address then "[${address}]" else address;
    in
    "${host}:${toString (validator.lightClientRpc.basePort + index)}";

  mkOtelEnv =
    validator:
    hellas.mkOtelEnv {
      inherit lib;
      inherit (validator) otel;
    };

  mkConfigFile =
    validator: index:
    let
      cli = getExe validator.package;
      addressesFlag = optionalString (
        validator.addresses != [ ]
      ) "--addresses ${escapeShellArg (concatStringsSep "," validator.addresses)}";
      seedFlag = optionalString (validator.seed != null) "--seed ${toString validator.seed}";
      genesisFlag = optionalString (
        validator.genesis != null
      ) "--genesis ${escapeShellArg validator.genesis}";
      relayFlags = concatStringsSep " " (
        map (url: "--relay-url ${escapeShellArg url}") validator.relayUrls
      );
      allocationFlags = concatStringsSep " " (
        map (
          allocation:
          "--genesis-allocation ${escapeShellArg "${allocation.address}:${toString allocation.balance}"}"
        ) validator.genesisAllocations
      );
      lightClientFlag = optionalString validator.lightClientRpc.enable "--light-client-bind ${escapeShellArg (lightClientBind validator index)}";
    in
    pkgs.runCommand "hellas-validator-${toString index}.toml" { } ''
      ${cli} chain validator config \
        --validators ${toString validator.totalValidators} \
        --validator ${toString index} \
        --start-port ${toString validator.startPort} \
        ${seedFlag} \
        ${addressesFlag} \
        ${relayFlags} \
        --metrics-port ${toString (validator.metricsBasePort + index)} \
        ${lightClientFlag} \
        ${genesisFlag} \
        ${allocationFlags} \
        > "$out"
      ${cli} chain validator check-config --config "$out"
    '';

  validatorOptions =
    { config, ... }:
    {
      options = {
        enable = mkEnableOption "Hellas validator cluster";
        package = mkOption {
          type = types.package;
          default = self.packages.${pkgs.stdenv.hostPlatform.system}.cli-validator.override {
            otel = config.otel.enable;
          };
          defaultText = literalExpression "self.packages.\${system}.cli-validator";
          description = "Hellas CLI package built with the validator feature.";
        };
        nodes = mkOption {
          type = types.ints.positive;
          default = 6;
          description = "Number of validator processes on this machine.";
        };
        totalValidators = mkOption {
          type = types.ints.positive;
          description = "Total validators in the network; defaults to nodes.";
        };
        nodeOffset = mkOption {
          type = types.ints.unsigned;
          default = 0;
          description = "First validator index assigned to this machine.";
        };
        startPort = mkOption {
          type = types.port;
          default = 31900;
          description = "Base consensus P2P port.";
        };
        metricsBasePort = mkOption {
          type = types.port;
          default = 9090;
          description = "Base Prometheus metrics port.";
        };
        lightClientRpc = {
          enable = mkEnableOption "a direct light-client RPC listener for every validator";
          bindAddress = mkOption {
            type = types.strMatching "[0-9A-Fa-f:.]+";
            default = "127.0.0.1";
            example = "0.0.0.0";
            description = ''
              Numeric IPv4 or IPv6 address, without brackets, on which each
              validator listens for direct light-client RPC connections.
              Loopback is the safe default; use a private interface address
              explicitly when workers run on another machine.
            '';
          };
          basePort = mkOption {
            type = types.port;
            default = 31246;
            description = ''
              Base light-client RPC port. Validator index N listens on
              basePort + N, so nodeOffset remains stable across machines.
            '';
          };
          openFirewall = mkOption {
            type = types.bool;
            default = false;
            description = ''
              Open the generated light-client RPC ports on the wg0 firewall
              interface. This is deliberately independent from enable and
              defaults off; enable it only for validators serving workers
              over the private deployment network.
            '';
          };
        };
        seed = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "Deterministic development validator seed.";
        };
        genesis = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = "Canonical genesis JSON embedded in every validator config.";
        };
        addresses = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = "Validator host addresses in canonical genesis order.";
        };
        relayUrls = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = "Relay or indexer WebSocket origins served by each validator.";
        };
        genesisAllocations = mkOption {
          type = types.listOf (
            types.submodule {
              options = {
                address = mkOption { type = types.str; };
                balance = mkOption { type = types.ints.unsigned; };
              };
            }
          );
          default = [ ];
          description = "Inline allocations for ad-hoc networks without a genesis file.";
        };
        runtimeConfigFiles = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = ''
            Complete validator TOML files supplied at runtime, one per local
            node, normally from sops-nix. Each file is copied into the
            service's private systemd credential directory and never enters
            the Nix store.
          '';
        };
        logLevel = mkOption {
          type = types.str;
          default = "info";
          description = "RUST_LOG directive.";
        };
        environment = mkOption {
          type = types.attrsOf types.str;
          default = { };
          description = "Additional environment variables.";
        };
        stateGeneration = mkOption {
          type = types.int;
          default = 0;
          description = ''
            Idempotent state reset generation. A positive generation wipes a
            validator's state exactly once when it changes.
          '';
        };
        memoryMax = mkOption {
          type = types.nullOr types.str;
          default = null;
          example = "2G";
          description = "Optional systemd MemoryMax for each validator.";
        };
        otel = hellas.otelOptions {
          inherit lib;
          cfg = config.otel;
          serviceName = "hellas-validator";
        };
      };

      config.totalValidators = mkDefault config.nodes;
    };

  enabledValidators = filterAttrs (_: validator: validator.enable) cfg;
in
{
  options.services.hellas-chain-validators = mkOption {
    type = types.attrsOf (types.submodule validatorOptions);
    default = { };
    description = "Hellas validator clusters keyed by deployment name.";
  };

  config = mkIf (enabledValidators != { }) {
    assertions = concatLists (
      mapAttrsToList (name: validator: [
        {
          assertion =
            validator.addresses == [ ] || builtins.length validator.addresses == validator.totalValidators;
          message = "services.hellas-chain-validators.${name}.addresses must contain one entry per validator.";
        }
        {
          assertion = validator.genesis == null || validator.seed != null;
          message = "services.hellas-chain-validators.${name}.genesis requires a deterministic seed.";
        }
        {
          assertion = validator.genesis == null || validator.genesisAllocations == [ ];
          message = "services.hellas-chain-validators.${name} cannot combine genesis with genesisAllocations.";
        }
        {
          assertion =
            validator.runtimeConfigFiles == [ ]
            || builtins.length validator.runtimeConfigFiles == validator.nodes;
          message = "services.hellas-chain-validators.${name}.runtimeConfigFiles must contain one file per local node.";
        }
        {
          assertion =
            validator.runtimeConfigFiles == [ ]
            || (
              validator.seed == null
              && validator.genesis == null
              && validator.genesisAllocations == [ ]
              && validator.addresses == [ ]
              && validator.relayUrls == [ ]
            );
          message = "services.hellas-chain-validators.${name}.runtimeConfigFiles cannot be combined with generated-config options.";
        }
        {
          assertion = validator.runtimeConfigFiles == [ ] || !validator.lightClientRpc.enable;
          message = "services.hellas-chain-validators.${name}.lightClientRpc.enable requires generated validator configs.";
        }
        {
          assertion =
            !validator.lightClientRpc.enable
            || validator.lightClientRpc.basePort + validator.nodeOffset + validator.nodes - 1 <= 65535;
          message = "services.hellas-chain-validators.${name}.lightClientRpc port range exceeds 65535.";
        }
        {
          assertion =
            !validator.lightClientRpc.enable
            ||
              lib.intersectLists (localPorts validator validator.lightClientRpc.basePort) (
                localPorts validator validator.startPort ++ localPorts validator validator.metricsBasePort
              ) == [ ];
          message = "services.hellas-chain-validators.${name}.lightClientRpc ports overlap consensus or metrics ports.";
        }
        {
          assertion = validator.lightClientRpc.enable || !validator.lightClientRpc.openFirewall;
          message = "services.hellas-chain-validators.${name}.lightClientRpc.openFirewall requires lightClientRpc.enable.";
        }
      ]) enabledValidators
    );

    networking.firewall.interfaces.wg0.allowedTCPPorts = concatLists (
      mapAttrsToList (
        _: validator:
        localPorts validator validator.metricsBasePort
        ++ localPorts validator validator.startPort
        ++ lib.optionals (validator.lightClientRpc.enable && validator.lightClientRpc.openFirewall) (
          localPorts validator validator.lightClientRpc.basePort
        )
      ) enabledValidators
    );

    systemd.services = mkMerge (
      mapAttrsToList (
        name: validator:
        builtins.listToAttrs (
          genList (
            localIndex:
            let
              index = validator.nodeOffset + localIndex;
              serviceName = "hellas-validator-${name}-node${toString index}";
              stateDirectory = "hellas-validator-${name}/node${toString index}";
              usesRuntimeConfig = validator.runtimeConfigFiles != [ ];
              configFile = if usesRuntimeConfig then "%d/validator-config" else mkConfigFile validator index;
            in
            {
              name = serviceName;
              value = {
                description = "Hellas Validator ${name} Node ${toString index}";
                wantedBy = [ "multi-user.target" ];
                after = [ "network-online.target" ];
                wants = [ "network-online.target" ];
                environment = mkOtelEnv validator // validator.environment // { RUST_LOG = validator.logLevel; };
                startLimitBurst = 5;
                startLimitIntervalSec = 60;
                serviceConfig = {
                  ExecStart = "${getExe validator.package} chain validator run --config ${configFile}";
                  Type = "simple";
                  Restart = "on-failure";
                  RestartSec = 5;
                  DynamicUser = true;
                  StateDirectory = stateDirectory;
                  Environment = [ "XDG_DATA_HOME=%S/${stateDirectory}" ];
                  CapabilityBoundingSet = [ "" ];
                  AmbientCapabilities = [ "" ];
                  NoNewPrivileges = true;
                  LockPersonality = true;
                  MemoryDenyWriteExecute = true;
                  RestrictRealtime = true;
                  RestrictSUIDSGID = true;
                  RestrictNamespaces = true;
                  RestrictAddressFamilies = [
                    "AF_INET"
                    "AF_INET6"
                    "AF_UNIX"
                  ];
                  RemoveIPC = true;
                  PrivateTmp = true;
                  PrivateDevices = true;
                  PrivateUsers = true;
                  PrivateMounts = true;
                  ProtectSystem = "strict";
                  ProtectHome = true;
                  ProtectHostname = true;
                  ProtectClock = true;
                  ProtectKernelLogs = true;
                  ProtectKernelModules = true;
                  ProtectKernelTunables = true;
                  ProtectControlGroups = true;
                  ProtectProc = "invisible";
                  ProcSubset = "pid";
                  DeviceAllow = "";
                  DevicePolicy = "closed";
                  SystemCallArchitectures = "native";
                  SystemCallFilter = [
                    "@system-service"
                    "~@privileged"
                    "~@resources"
                  ];
                  UMask = "0077";
                }
                // optionalAttrs usesRuntimeConfig {
                  LoadCredential = [
                    "validator-config:${builtins.elemAt validator.runtimeConfigFiles localIndex}"
                  ];
                }
                // optionalAttrs (validator.memoryMax != null) { MemoryMax = validator.memoryMax; }
                // optionalAttrs (validator.stateGeneration > 0) {
                  ExecStartPre =
                    let
                      resetState = pkgs.writeShellScript "hellas-validator-state-check" ''
                        set -eu
                        stamp="$STATE_DIRECTORY/.state-generation"
                        target=${toString validator.stateGeneration}
                        current=$(${pkgs.coreutils}/bin/cat "$stamp" 2>/dev/null || echo 0)
                        if [ "$current" != "$target" ]; then
                          ${pkgs.findutils}/bin/find -L "$STATE_DIRECTORY" -mindepth 1 -delete
                          echo "$target" > "$stamp"
                        fi
                      '';
                    in
                    "+${resetState}";
                };
              };
            }
          ) validator.nodes
        )
      ) enabledValidators
    );
  };
}
