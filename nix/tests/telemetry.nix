{ pkgs, lib }:
test:
let
  traceFile = "/var/lib/opentelemetry-collector/traces.jsonl";
  environment = {
    OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = "http://127.0.0.1:4318/v1/traces";
    OTEL_TRACES_SAMPLER = "always_on";
    OTEL_BSP_SCHEDULE_DELAY = "100";
    OTEL_METRICS_EXPORTER = "none";
    OTEL_LOGS_EXPORTER = "none";
    OTEL_RESOURCE_ATTRIBUTES = "test.suite.name=${test.name}";
  };
  indent = text: lib.concatMapStringsSep "\n" (line: "    ${line}") (lib.splitString "\n" text);
in
pkgs.testers.runNixOSTest (
  test
  // {
    defaults = {
      imports = [ (test.defaults or { }) ];
      environment.variables = environment;
      systemd.globalEnvironment = environment;
      services.opentelemetry-collector = {
        enable = true;
        package = pkgs.opentelemetry-collector-contrib;
        validateConfigFile = true;
        settings = {
          receivers.otlp.protocols.http.endpoint = "127.0.0.1:4318";
          exporters.file = {
            path = traceFile;
            format = "json";
            flush_interval = "100ms";
          };
          service.pipelines.traces = {
            receivers = [ "otlp" ];
            exporters = [ "file" ];
          };
        };
      };
      systemd.services.opentelemetry-collector.before = [
        "hellas.service"
        "hellas-gateway.service"
      ];
    };
    testScript = ''
      import json

      cleanup_errors = []

      def shutdown(vm, command, timeout=30):
          status, output = vm.execute(command, timeout=timeout)
          if status != 0:
              cleanup_errors.append(f"{vm.name}: {command}: {output}")

      try:
          start_all()
          for vm in machines:
              vm.wait_for_unit("opentelemetry-collector.service")
              vm.wait_for_open_port(4318)
      ${indent test.testScript}
      finally:
          # Keep diagnostics even when an assertion fails. Producers stop first
          # so the collector can flush their final batches before copying.
          for vm in machines:
              if not vm.is_up():
                  continue
              for unit in ["hellas.service", "hellas-gateway.service"]:
                  if vm.execute(f"systemctl is-active --quiet {unit}")[0] == 0:
                      shutdown(vm, f"systemctl stop {unit}")
              shutdown(vm, "pkill -TERM -x hellas-cli || test $? -eq 1")
              shutdown(vm, "timeout 45 sh -c 'while pgrep -x hellas-cli >/dev/null; do sleep 0.1; done'", timeout=50)
              shutdown(vm, "systemctl stop opentelemetry-collector.service")
              vm.succeed("journalctl -u opentelemetry-collector.service --no-pager > /tmp/collector.log")
              vm.copy_from_machine("/tmp/collector.log", f"traces/{vm.name}")
              products = vm.out_dir / "nix-support" / "hydra-build-products"
              products.parent.mkdir(exist_ok=True)
              with products.open("a") as output:
                  output.write(f"file log {vm.out_dir}/traces/{vm.name}/collector.log\n")
              if vm.execute("test -f ${traceFile}")[0] == 0:
                  vm.copy_from_machine("${traceFile}", f"traces/{vm.name}")
                  artifact = vm.out_dir / "traces" / vm.name / "traces.jsonl"
                  with products.open("a") as output:
                      output.write(f"file json {artifact}\n")
          for error in cleanup_errors:
              print(error)

      assert not cleanup_errors, "telemetry shutdown failed; retained available diagnostics"
      # A successful check must leave actual exported spans, not an empty file.
      for vm in machines:
          artifact = vm.out_dir / "traces" / vm.name / "traces.jsonl"
          spans = [
              span
              for line in (artifact.read_text() if artifact.exists() else "").splitlines()
              for resource in json.loads(line).get("resourceSpans", [])
              for scope in resource.get("scopeSpans", [])
              for span in scope.get("spans", [])
          ]
          assert spans, f"no spans exported by {vm.name}"
    '';
  }
)
