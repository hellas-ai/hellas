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

        ! ${package}/bin/hellas llm --help
        ${package}/bin/hellas --version
        ${package}/bin/hellas --help | grep -F "Hellas node CLI"
        ${package}/bin/hellas gateway --help | grep -F -- "--wrap"
        ${package}/bin/hellas gateway --help | grep -F -- "--text-model <FILE>"
        ${package}/bin/hellas gateway --help | grep -F -- "--responses-overrides"
        ${package}/bin/hellas gateway --help | grep -F -- "--trust-policy"
        ${package}/bin/hellas gateway --help | grep -F -- "--trust-store"
        ${package}/bin/hellas serve --help | grep -F -- "--content <PATH>"
        ${package}/bin/hellas serve --help | grep -F -- "--identity <IDENTITY>"
        ${package}/bin/hellas serve --help | grep -F -- "--content-root <DIR>"
        ${package}/bin/hellas serve --help | grep -F -- "--content-index <FILE>"
        ${package}/bin/hellas serve --help | grep -F -- "--gpu-session-programs"
        ${package}/bin/hellas serve --help | grep -F -- "--gpu-session-asset-bytes"
        ${package}/bin/hellas serve --help | grep -F -- "--paid-work-config"
        ! ${package}/bin/hellas serve --help | grep -F -- "--gfx"
        ${package}/bin/hellas identity --help | grep -F -- "show-enrollment-id"

        ${package}/bin/hellas --identity "$TMPDIR/identity" --software-root \
          monitor --timeout-secs 1 >/dev/null 2>&1 || true
        ${package}/bin/hellas --identity "$TMPDIR/identity" identity show-node-id \
          | grep -E '^[0-9a-f]{64}$'
        ${package}/bin/hellas --identity "$TMPDIR/identity" identity show-enrollment-id \
          | grep -E '^[0-9a-f]{64}$'

        touch "$out"
      '';
}
