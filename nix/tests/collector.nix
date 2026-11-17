{ pkgs }:
# VM telemetry needs OTLP/HTTP input and JSON files. Generate that distribution
# with upstream's builder and the versions already locked by nixpkgs' collector.
# Keep its module cache: changing components does not change dependency versions.
pkgs.opentelemetry-collector-contrib.overrideAttrs (old: {
  pname = "hellas-test-collector";
  goModules = pkgs.opentelemetry-collector-contrib.goModules;
  postInstall = pkgs.lib.replaceStrings [ old.pname ] [ "hellas-test-collector" ] old.postInstall;
  meta = old.meta // {
    mainProgram = "hellas-test-collector";
  };
  postConfigure = (old.postConfigure or "") + ''
    gomod() { go list -m -f '{{.Path}} {{.Version}}' "$1"; }
    cat > collector.yaml <<EOF_MANIFEST
    dist:
      name: hellas-test-collector
      module: $(go list -m)
      description: Hellas VM trace collector
      version: ${old.version}
      output_path: "$TMPDIR/collector"
    receivers:
      - gomod: $(gomod go.opentelemetry.io/collector/receiver/otlpreceiver)
    exporters:
      - gomod: $(gomod github.com/open-telemetry/opentelemetry-collector-contrib/exporter/fileexporter)
    providers:
      - gomod: $(gomod go.opentelemetry.io/collector/confmap/provider/envprovider)
      - gomod: $(gomod go.opentelemetry.io/collector/confmap/provider/fileprovider)
      - gomod: $(gomod go.opentelemetry.io/collector/confmap/provider/yamlprovider)
    EOF_MANIFEST
    ${pkgs.lib.getExe pkgs.opentelemetry-collector-builder} \
      --config collector.yaml --skip-get-modules --skip-compilation
    cp "$TMPDIR/collector/"*.go .
  '';
})
