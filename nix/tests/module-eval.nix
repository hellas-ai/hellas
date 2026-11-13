{
  self,
  pkgs,
  lib,
  package,
}:
let
  plainPkgs = import pkgs.path { system = pkgs.stdenv.hostPlatform.system; };
  hellasModule = import ../modules/hellas.nix { inherit self; };
  runtimeEnvironmentWrapper = hellasModule.mkRuntimeEnvironmentWrapper pkgs;
  runtimeEnvironmentStoreFile = pkgs.writeText "hellas-runtime-environment-store-fixture" "TOKEN=store-secret";
  eval =
    settings:
    import (pkgs.path + "/nixos/lib/eval-config.nix") {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        self.nixosModules.default
        {
          nixpkgs.pkgs = plainPkgs;
          system.stateVersion = "26.05";
          services.hellas = {
            inherit package;
          }
          // settings;
        }
      ];
    };
  evalProvider = settings: eval ({ enable = true; } // settings);
  evalGateway =
    settings:
    eval {
      gateway = {
        enable = true;
        models = [
          "/srv/models/qwen.gguf"
          "flux@friend"
          "gpt-5@upstream"
        ];
        upstreams.upstream = {
          url = "https://api.example.com/v1";
          keyFile = "/run/secrets/upstream.key";
        };
      }
      // settings;
    };
  assertion =
    text: evaluation:
    (lib.findFirst (
      item: lib.hasInfix text item.message
    ) (throw "missing module assertion: ${text}") evaluation.config.assertions).assertion;
  defaultProviderService = (evalProvider { }).config.systemd.services.hellas;
  gateway = (evalGateway { }).config.systemd.services.hellas-gateway;
  remote = (evalGateway { models = [ "gpt-5@upstream" ]; }).config.systemd.services.hellas-gateway;
  custom = (evalGateway { home = "/srv/gateway-state"; }).config.systemd.services.hellas-gateway;
  metrics =
    (eval {
      otel.enable = true;
      gateway = {
        enable = true;
        models = [ "gpt-5@upstream" ];
        metricsPort = 9401;
      };
    }).config.systemd.services.hellas-gateway;
  validatorPackageFixture =
    (pkgs.writeShellScriptBin "hellas" ''
      set -eu

      test "$1" = chain
      test "$2" = validator
      action="$3"
      shift 3

      case "$action" in
        config)
          while [ "$#" -gt 0 ]; do
            flag="$1"
            value="$2"
            shift 2
            printf '%s=%s\n' "$flag" "$value"
          done
          ;;
        check-config)
          test "$1" = --config
          test -s "$2"
          ;;
        *)
          exit 64
          ;;
      esac
    '').overrideAttrs
      (_: {
        meta.mainProgram = "hellas";
      });
  evalValidators =
    validator:
    import (pkgs.path + "/nixos/lib/eval-config.nix") {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        self.nixosModules.validators
        {
          nixpkgs.pkgs = plainPkgs;
          system.stateVersion = "26.05";
          services.hellas-chain-validators.devnet = {
            enable = true;
            package = validatorPackageFixture;
          }
          // validator;
        }
      ];
    };
  paidWorkValidators = evalValidators {
    nodes = 3;
    totalValidators = 6;
    nodeOffset = 2;
    startPort = 31900;
    metricsBasePort = 9090;
    metricsBindAddress = "10.100.0.10";
    seed = 7;
    lightClientRpc = {
      enable = true;
      bindAddress = "0.0.0.0";
      basePort = 31246;
      openFirewall = true;
    };
    chainSync = {
      enable = true;
      bindAddress = "10.100.0.10";
      basePort = 31346;
      openFirewall = true;
    };
    archiveBlocks = 1500000;
  };
  loopbackValidators = evalValidators {
    nodes = 1;
    seed = 7;
    lightClientRpc.enable = true;
  };
  validatorsWithoutRpc = evalValidators {
    nodes = 1;
    seed = 7;
  };
  overflowingValidatorRpc = evalValidators {
    nodes = 2;
    nodeOffset = 1;
    seed = 7;
    lightClientRpc = {
      enable = true;
      basePort = 65535;
    };
  };
  collidingValidatorRpc = evalValidators {
    nodes = 2;
    seed = 7;
    startPort = 31900;
    lightClientRpc = {
      enable = true;
      basePort = 31900;
    };
  };
  unconfiguredRuntimeRpc = evalValidators {
    nodes = 1;
    runtimeConfigFiles = [ "/run/hellas/validator.toml" ];
    lightClientRpc.enable = true;
  };
  unopenedValidatorRpc = evalValidators {
    nodes = 1;
    seed = 7;
    lightClientRpc.openFirewall = true;
  };
  overflowingChainSync = evalValidators {
    nodes = 2;
    nodeOffset = 1;
    seed = 7;
    chainSync = {
      enable = true;
      basePort = 65535;
    };
  };
  unopenedChainSync = evalValidators {
    nodes = 1;
    seed = 7;
    chainSync.openFirewall = true;
  };
  validatorAssertion =
    message: evaluation:
    lib.findFirst (
      assertion: lib.hasInfix message assertion.message
    ) (throw "missing validator assertion containing: ${message}") evaluation.config.assertions;
  validatorConfigPath =
    service:
    let
      matched = builtins.match ".* --config (.*)" service.serviceConfig.ExecStart;
    in
    if matched == null then throw "validator ExecStart has no config" else builtins.head matched;
  paidWorkValidatorServices = paidWorkValidators.config.systemd.services;
  validatorConfig2 = validatorConfigPath paidWorkValidatorServices."hellas-validator-devnet-node2";
in
{
  provider-content-eval =
    assert lib.hasInfix "serve --port" defaultProviderService.serviceConfig.ExecStart;
    assert !(lib.hasInfix "--model" defaultProviderService.serviceConfig.ExecStart);
    assert lib.hasInfix "gateway --bind 127.0.0.1:8080" gateway.serviceConfig.ExecStart;
    assert lib.hasInfix "--model /srv/models/qwen.gguf --model flux@friend --model gpt-5@upstream"
      gateway.serviceConfig.ExecStart;
    assert lib.hasInfix (lib.escapeShellArgs [
      "--upstream"
      "upstream=https://api.example.com/v1,key-file=/run/secrets/upstream.key"
    ]) gateway.serviceConfig.ExecStart;
    assert !(lib.hasInfix "--config" gateway.serviceConfig.ExecStart);
    assert !(lib.hasInfix "--local" gateway.serviceConfig.ExecStart);
    assert lib.hasInfix "--metrics-port 9401 --metrics-addr 127.0.0.1" metrics.serviceConfig.ExecStart;
    assert gateway.serviceConfig.ReadOnlyPaths == [ "/srv/models/qwen.gguf" ];
    assert lib.elem "/run/secrets/upstream.key" gateway.unitConfig.RequiresMountsFor;
    assert custom.serviceConfig.ReadWritePaths == [ "/srv/gateway-state" ];
    assert gateway.serviceConfig.RuntimeDirectoryMode == "0700";
    assert gateway.serviceConfig.StateDirectoryMode == "0700";
    assert gateway.serviceConfig.UMask == "0077";
    assert gateway.serviceConfig ? LimitMEMLOCK;
    assert !(remote.serviceConfig ? LimitMEMLOCK);
    assert
      !(assertion "must name at least one" (evalGateway {
        models = [ ];
      }));
    assert
      !(assertion "absolute runtime paths" (evalGateway {
        models = [ "relative.gguf" ];
      }));
    assert
      !(assertion "fixed port" (evalGateway {
        port = 0;
        openFirewall = true;
      }));
    assert
      !(assertion "runtime data outside" (evalGateway {
        models = [ "${builtins.storeDir}/model.gguf" ];
      }));
    assert
      !(assertion "runtime data outside" (evalGateway {
        upstreams.upstream = {
          url = "https://example.com";
          keyFile = "${builtins.storeDir}/key";
        };
      }));
    assert
      !(assertion "gateway writable journal paths" (evalGateway {
        home = "/";
      }));
    assert
      !(assertion "services.hellas.gateway.extraArgs" (evalGateway {
        extraArgs = [ "--model=/run/model" ];
      }));
    assert
      !(assertion "services.hellas.extraArgs" (evalProvider {
        extraArgs = [ "--home=/run/home" ];
      }));
    assert
      !(assertion "metrics ports require" (evalGateway {
        metricsPort = 9401;
      }));
    assert lib.all (path: !(hellasModule.runtimePathIsOutsideStore lib path)) [
      "${builtins.storeDir}/secret"
      "/.${builtins.storeDir}/secret"
      "/run/../..${builtins.storeDir}/secret"
      (builtins.appendContext "/run/secrets/key" (builtins.getContext (toString package)))
    ];
    assert lib.all (value: !(hellasModule.runtimeStringIsOutsideStore lib value)) [
      "file:/run/key"
      " FILE:/run/key"
      "fi\tle:/run/key"
      "${builtins.storeDir}/secret"
    ];
    pkgs.runCommand "hellas-daemon-module-eval" { } ''
      umask 077
      environment_file="$PWD/provider.env"
      printf '%s\n' \
        '# literal runtime environment' \
        'TOKEN=runtime-secret-not-in-wrapper' \
        'COMPLEX=value with spaces=#literal=tail' \
        'LITERAL=$(touch should-not-exist)' \
        'EMPTY=' > "$environment_file"

      actual="$(${runtimeEnvironmentWrapper} "$environment_file" \
        ${pkgs.bash}/bin/bash -c 'printf "%s|%s|%s|%s" "$TOKEN" "$COMPLEX" "$LITERAL" "$EMPTY"')"
      test "$actual" = 'runtime-secret-not-in-wrapper|value with spaces=#literal=tail|$(touch should-not-exist)|'
      test ! -e "$PWD/should-not-exist"
      ! ${pkgs.gnugrep}/bin/grep -F 'runtime-secret-not-in-wrapper' ${runtimeEnvironmentWrapper}
      ! ${pkgs.gnugrep}/bin/grep -F '/Users/hellas/.config/hellas/provider.env' ${runtimeEnvironmentWrapper}

      printf '%s\n' 'INSECURE=value' > "$PWD/insecure-mode.env"
      chmod 0644 "$PWD/insecure-mode.env"
      if ${runtimeEnvironmentWrapper} "$PWD/insecure-mode.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      printf '%s\n' 'SYMLINK=value' > "$PWD/symlink-target.env"
      ln -s "$PWD/symlink-target.env" "$PWD/symlink.env"
      if ${runtimeEnvironmentWrapper} "$PWD/symlink.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      ${pkgs.coreutils}/bin/mkfifo "$PWD/fifo.env"
      chmod 0600 "$PWD/fifo.env"
      fifo_status=0
      ${pkgs.coreutils}/bin/timeout 2 \
        ${runtimeEnvironmentWrapper} "$PWD/fifo.env" ${pkgs.coreutils}/bin/true \
        2>/dev/null || fifo_status=$?
      test "$fifo_status" -ne 0
      test "$fifo_status" -ne 124

      ln -s ${builtins.dirOf runtimeEnvironmentStoreFile} "$PWD/store-parent"
      if ${runtimeEnvironmentWrapper} \
        "$PWD/store-parent/${builtins.baseNameOf runtimeEnvironmentStoreFile}" \
        ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      printf '%s\n' 'MALFORMED' > "$PWD/malformed.env"
      if ${runtimeEnvironmentWrapper} "$PWD/malformed.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      printf '%s\n' 'DUPLICATE=one' 'DUPLICATE=two' > "$PWD/duplicate.env"
      if ${runtimeEnvironmentWrapper} "$PWD/duplicate.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      printf 'CR=value\r\n' > "$PWD/carriage-return.env"
      if ${runtimeEnvironmentWrapper} "$PWD/carriage-return.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      printf 'NUL=value\000suffix\n' > "$PWD/nul.env"
      if ${runtimeEnvironmentWrapper} "$PWD/nul.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      if ${runtimeEnvironmentWrapper} "$PWD/missing.env" ${pkgs.coreutils}/bin/true 2>/dev/null; then
        exit 1
      fi

      touch "$out"
    '';

  validator-module-eval =
    assert lib.hasInfix "--durability crash" defaultProviderService.serviceConfig.ExecStart;
    assert lib.hasInfix "--durability power"
      (evalProvider { durability = "power"; }).config.systemd.services.hellas.serviceConfig.ExecStart;
    assert
      paidWorkValidators.config.networking.firewall.interfaces.wg0.allowedTCPPorts == [
        9092
        9093
        9094
        31248
        31249
        31250
        31902
        31903
        31904
      ];
    assert loopbackValidators.config.networking.firewall.interfaces.wg0.allowedTCPPorts == [ 31900 ];
    assert validatorsWithoutRpc.config.networking.firewall.interfaces.wg0.allowedTCPPorts == [ 31900 ];
    assert
      !(validatorAssertion "lightClientRpc port range exceeds 65535" overflowingValidatorRpc).assertion;
    assert !(validatorAssertion "lightClientRpc ports overlap" collidingValidatorRpc).assertion;
    assert
      !(validatorAssertion "requires generated validator configs" unconfiguredRuntimeRpc).assertion;
    assert !(validatorAssertion "openFirewall requires" unopenedValidatorRpc).assertion;
    assert
      paidWorkValidators.config.networking.firewall.interfaces.wg0.allowedUDPPorts == [
        31348
        31349
        31350
      ];
    assert validatorsWithoutRpc.config.networking.firewall.interfaces.wg0.allowedUDPPorts == [ ];
    assert !(validatorAssertion "chainSync port range exceeds 65535" overflowingChainSync).assertion;
    assert !(validatorAssertion "chainSync.openFirewall requires" unopenedChainSync).assertion;
    assert lib.hasSuffix "chain validator run --config ${validatorConfig2}"
      paidWorkValidatorServices."hellas-validator-devnet-node2".serviceConfig.ExecStart;
    pkgs.runCommand "hellas-validator-module-eval" { } ''
      command2=${
        lib.escapeShellArg paidWorkValidatorServices."hellas-validator-devnet-node2".serviceConfig.ExecStart
      }
      command3=${
        lib.escapeShellArg paidWorkValidatorServices."hellas-validator-devnet-node3".serviceConfig.ExecStart
      }
      command4=${
        lib.escapeShellArg paidWorkValidatorServices."hellas-validator-devnet-node4".serviceConfig.ExecStart
      }
      loopback_command=${
        lib.escapeShellArg
          loopbackValidators.config.systemd.services."hellas-validator-devnet-node0".serviceConfig.ExecStart
      }
      disabled_command=${
        lib.escapeShellArg
          validatorsWithoutRpc.config.systemd.services."hellas-validator-devnet-node0".serviceConfig.ExecStart
      }
      config2="''${command2##*--config }"
      config3="''${command3##*--config }"
      config4="''${command4##*--config }"
      loopback_config="''${loopback_command##*--config }"
      disabled_config="''${disabled_command##*--config }"

      ${pkgs.gnugrep}/bin/grep -Fx -- '--validator=2' "$config2"
      ${pkgs.gnugrep}/bin/grep -Fx -- '--metrics-port=9092' "$config2"
      ${pkgs.gnugrep}/bin/grep -Fx -- '--metrics-bind-address=10.100.0.10' "$config2"
      ${pkgs.gnugrep}/bin/grep -Fx -- '--metrics-bind-address=127.0.0.1' "$loopback_config"
      ${pkgs.gnugrep}/bin/grep -Fx -- '--light-client-bind=0.0.0.0:31248' "$config2"
      ${pkgs.gnugrep}/bin/grep -Fx -- '--chain-sync-bind=10.100.0.10:31348' "$config2"
      ${pkgs.gnugrep}/bin/grep -Fx -- '--archive-blocks=1500000' "$config2"

      ${pkgs.gnugrep}/bin/grep -Fx -- '--validator=3' "$config3"
      ${pkgs.gnugrep}/bin/grep -Fx -- '--light-client-bind=0.0.0.0:31249' "$config3"
      ${pkgs.gnugrep}/bin/grep -Fx -- '--chain-sync-bind=10.100.0.10:31349' "$config3"

      ${pkgs.gnugrep}/bin/grep -Fx -- '--validator=4' "$config4"
      ${pkgs.gnugrep}/bin/grep -Fx -- '--light-client-bind=0.0.0.0:31250' "$config4"
      ${pkgs.gnugrep}/bin/grep -Fx -- '--chain-sync-bind=10.100.0.10:31350' "$config4"

      ${pkgs.gnugrep}/bin/grep -Fx -- '--light-client-bind=127.0.0.1:31246' "$loopback_config"
      ! ${pkgs.gnugrep}/bin/grep -F -- '--light-client-bind' "$disabled_config"
      ! ${pkgs.gnugrep}/bin/grep -F -- '--chain-sync-bind' "$disabled_config"
      ! ${pkgs.gnugrep}/bin/grep -F -- '--chain-sync-bind' "$loopback_config"
      ! ${pkgs.gnugrep}/bin/grep -F -- '--archive-blocks' "$disabled_config"

      touch "$out"
    '';
}
