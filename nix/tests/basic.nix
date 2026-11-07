{
  pkgs,
  package,
}:
{
  basic =
    pkgs.runCommand "hellas-cli-basic"
      {
        nativeBuildInputs = with pkgs; [
          coreutils
          gnugrep
        ];
      }
      ''
        export HOME="$TMPDIR/home"
        mkdir -p "$HOME"

        ${package}/bin/hellas --version
        ${package}/bin/hellas --help | grep -F "Hellas node CLI"
        ${package}/bin/hellas --help | grep -F -- "--chain <CHAIN>"
        ${package}/bin/hellas --help | grep -F -- "--chain-config <FILE>"
        ${package}/bin/hellas gateway --help | grep -F -- "--wrap"
        ${package}/bin/hellas gateway --help | grep -F -- "--text-model <FILE>"
        ${package}/bin/hellas gateway --help | grep -F -- "--responses-overrides"
        ${package}/bin/hellas gateway --help | grep -F -- "--trust-policy"
        ${package}/bin/hellas gateway --help | grep -F -- "--trust-store"
        ${package}/bin/hellas --help | grep -F -- "--home <DIR>"
        ${package}/bin/hellas serve --help | grep -F -- "--content-config <FILE>"
        ${package}/bin/hellas store --help | grep -F -- "acquire"
        ${package}/bin/hellas store pin --help | grep -F -- "set"
        ${package}/bin/hellas serve --help | grep -F -- "--gpu-session-programs"
        ${package}/bin/hellas serve --help | grep -F -- "--gpu-session-asset-bytes"
        ${package}/bin/hellas serve --help | grep -F -- "--paid-work-config"
        ! ${package}/bin/hellas serve --help | grep -F -- "--gfx"
        ${package}/bin/hellas identity --help | grep -F -- "show-enrollment-id"

        ${package}/bin/hellas --home "$TMPDIR/hellas-home" --software-root \
          monitor --timeout-secs 1 >/dev/null 2>&1 || true
        ${package}/bin/hellas --home "$TMPDIR/hellas-home" identity show-node-id \
          | grep -E '^[0-9a-f]{64}$'
        ${package}/bin/hellas --home "$TMPDIR/hellas-home" identity show-enrollment-id \
          | grep -E '^[0-9a-f]{64}$'

        touch "$out"
      '';
}
