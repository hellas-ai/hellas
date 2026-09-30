{
  pkgs,
  package,
  networkPackage,
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

        ! ${package}/bin/hellas-cli fetch --help
        ! ${package}/bin/hellas-cli llm --help
        ${package}/bin/hellas-cli --version
        ${package}/bin/hellas-cli --help | grep -F "Hellas node CLI"
        ${package}/bin/hellas-cli gateway --help | grep -F -- "--wrap"
        ${package}/bin/hellas-cli gateway --help | grep -F -- "--environment <FILE>"
        ${package}/bin/hellas-cli gateway --help | grep -F -- "--manifest-id <CONTENT_ID>"
        ${package}/bin/hellas-cli gateway --help | grep -F -- "--model <NAME>"
        ${package}/bin/hellas-cli gateway --help | grep -F -- "--tokenizer"
        ${package}/bin/hellas-cli gateway --help | grep -F -- "--stop-token"
        ${package}/bin/hellas-cli gateway --help | grep -F -- "--content <PATH>"
        ${package}/bin/hellas-cli gateway --help | grep -F -- "--content-root <DIR>"
        ${package}/bin/hellas-cli gateway --help | grep -F -- "codex-responses"
        ${package}/bin/hellas-cli gateway --help | grep -F -- "--apple-app-attest-cdhashes"
        ${package}/bin/hellas-cli gateway --help | grep -F -- "--apple-app-attest-app-id"
        ${package}/bin/hellas-cli environment build --help | grep -F -- "--program <CATENA_SOURCE>"
        ${package}/bin/hellas-cli environment verify --help | grep -F -- "--content-root <DIR>"
        ${package}/bin/hellas-cli environment verify --help | grep -F -- "--content-index <FILE>"
        ${package}/bin/hellas-cli environment verify --help | grep -F -- "--recheck"
        ${package}/bin/hellas-cli serve --help | grep -F -- "--content <PATH>"
        ${package}/bin/hellas-cli serve --help | grep -F -- "--identity <IDENTITY>"
        ${package}/bin/hellas-cli serve --help | grep -F -- "--content-root <DIR>"
        ${package}/bin/hellas-cli serve --help | grep -F -- "--content-index <FILE>"
        ${package}/bin/hellas-cli serve --help | grep -F -- "--gpu-session-programs"
        ${package}/bin/hellas-cli serve --help | grep -F -- "--gpu-session-asset-bytes"
        ${package}/bin/hellas-cli serve --help | grep -F -- "--gpu-max-generation-capacity"
        ${package}/bin/hellas-cli serve --help | grep -F -- "--gpu-max-generation-device-bytes"
        ${package}/bin/hellas-cli serve --help | grep -F -- "--gpu-compile-timeout-secs"
        ${package}/bin/hellas-cli serve --help | grep -F -- "--gpu-execution-timeout-secs"
        ${package}/bin/hellas-cli serve --help | grep -F -- "--work-config"
        ! ${package}/bin/hellas-cli serve --help | grep -F -- "--gfx"
        ${package}/bin/hellas-cli identity --help | grep -F -- "show-enrollment-id"

        # The ordinary package exposes environment tooling without
        # accidentally pulling in the local Catena evaluator.
        ${networkPackage}/bin/hellas-cli environment verify --help | grep -F -- "--content-root <DIR>"

        ${package}/bin/hellas-cli --identity "$TMPDIR/identity" --software-root \
          monitor --timeout-secs 1 >/dev/null 2>&1 || true
        ${package}/bin/hellas-cli --identity "$TMPDIR/identity" identity show-node-id \
          | grep -E '^[0-9a-f]{64}$'
        ${package}/bin/hellas-cli --identity "$TMPDIR/identity" identity show-enrollment-id \
          | grep -E '^[0-9a-f]{64}$'

        touch "$out"
      '';
}
