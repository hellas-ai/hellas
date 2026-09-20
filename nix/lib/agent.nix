{ pkgs }:
let
  inherit (pkgs) lib;
  make =
    {
      name,
      workspace,
      prompt,
      model,
      hellas,
      opencode ? pkgs.opencode,
      packages ? [ ],
      gatewayArgs ? [
        "--responses-backend"
        "proxy"
      ],
      date ? "1970-01-01",
    }:
    let
      promptFile = pkgs.writeText "${name}-prompt" prompt;
      # OpenCode includes today's date in every system prompt. Make it an
      # explicit build input while keeping its coding instructions intact.
      plugin = pkgs.writeText "hellas-agent-date.mjs" ''
        export default async () => ({
          "experimental.chat.system.transform": async (_, output) => {
            output.system = output.system.map(text =>
              text.replace(/Today's date: [^\n]*/g, "Today's date: ${date}"));
          }
        });
      '';
      config = pkgs.writeText "${name}-opencode.json" (
        builtins.toJSON {
          autoupdate = false;
          share = "disabled";
          permission = "allow";
          enabled_providers = [ "hellas" ];
          plugin = [ "file://${plugin}" ];
          agent.title.disable = true;
          agent.summary.disable = true;
          provider.hellas = {
            npm = "@ai-sdk/openai";
            options = {
              baseURL = "{env:OPENAI_BASE_URL}";
              apiKey = "{env:OPENAI_API_KEY}";
            };
            models.${model} = {
              name = model;
              limit = {
                context = 128000;
                output = 16384;
              };
            };
          };
        }
      );
      agent = pkgs.writeShellScript "${name}-agent" ''
        set -euo pipefail
        export OPENCODE_CONFIG_CONTENT="$(< ${config})"
        ${opencode}/bin/opencode run --model ${lib.escapeShellArg "hellas/${model}"} \
          --format json "$(< ${promptFile})" | tee /build/session.jsonl
        # OpenCode can exit zero after errors or an unrecognized SSE failure.
        if ! ${pkgs.jq}/bin/jq -s -e '
          all(.[]; .type != "error") and
          ([.[] | select(.type == "step_finish")] | last).part.reason == "stop"
        ' /build/session.jsonl >/dev/null; then
          echo "OpenCode did not finish successfully" >&2
          exit 1
        fi
      '';
      run = pkgs.writeShellScript "${name}-run" ''
        set -euo pipefail
        export PATH=${
          lib.makeBinPath (
            [
              pkgs.bash
              pkgs.coreutils
              pkgs.git
              pkgs.ripgrep
            ]
            ++ packages
          )
        }
        export HOME=/build/home
        export XDG_CONFIG_HOME=/build/home/config
        export XDG_DATA_HOME=/build/home/data
        export XDG_CACHE_HOME=/build/home/cache
        export TMPDIR=/build/tmp
        export TZ=UTC LC_ALL=C
        export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
        export OPENCODE_DISABLE_AUTOUPDATE=true OPENCODE_DISABLE_MODELS_FETCH=true
        export OPENCODE_DISABLE_PROJECT_CONFIG=true OPENCODE_EXPERIMENTAL_DISABLE_FILEWATCHER=true
        mkdir -p /build/workspace "$HOME" "$TMPDIR"
        cp -R ${workspace}/. /build/workspace/
        chmod -R u+w /build/workspace
        cd /build/workspace
        ${hellas}/bin/hellas-cli --identity /build/identity --software-root \
          --output-cache "$1" --store-dir "$2" gateway \
          ${lib.escapeShellArgs gatewayArgs} --wrap ${agent}
      '';
    in
    assert lib.assertMsg pkgs.stdenv.hostPlatform.isLinux
      "agent record/replay currently requires Linux";
    assert lib.assertMsg (
      builtins.match "[0-9]{4}-[0-9]{2}-[0-9]{2}" date != null
    ) "agent date must be YYYY-MM-DD";
    {
      inherit name run;
    };
in
{
  mkAgentRun =
    args@{ cache, ... }:
    let
      agent = make (builtins.removeAttrs args [ "cache" ]);
    in
    pkgs.runCommand agent.name { } ''
      ${agent.run} replay-only ${cache}
      mkdir -p "$out"
      cp -R /build/workspace/. "$out/"
    '';

  # Run this executable outside nix-build. The temporary /build mount gives
  # OpenCode and its tools the same absolute paths as the sandboxed replay.
  mkAgentRecord =
    args:
    let
      agent = make args;
    in
    pkgs.writeShellApplication {
      name = "${agent.name}-record";
      passthru.runner = agent.run;
      runtimeInputs = [
        pkgs.coreutils
        pkgs.bubblewrap
      ];
      text = ''
        if [ "$#" -ne 1 ]; then
          echo "usage: ${agent.name}-record STORE_DIRECTORY" >&2
          exit 2
        fi
        mkdir -p "$1"
        store_directory="$(realpath "$1")"
        run_directory="$(mktemp -d)"
        trap 'rm -rf -- "$run_directory"' EXIT
        bwrap --die-with-parent \
          --ro-bind /nix/store /nix/store \
          --ro-bind /etc/resolv.conf /etc/resolv.conf --dev /dev --proc /proc \
          --tmpfs /tmp --bind "$run_directory" /build \
          --bind "$store_directory" "$store_directory" --chdir /build \
          ${agent.run} record "$store_directory"
      '';
    };
}
