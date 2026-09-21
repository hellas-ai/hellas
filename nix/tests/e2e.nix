{
  self,
  pkgs,
  lib,
  package,
  validatorPackage,
}:
let
  inherit (pkgs.hellasLib) executorPort;
  hellasModule = import ../modules/nixos.nix { inherit self; };
  runTest = import ./telemetry.nix { inherit pkgs lib; };

  gatewayPort = 8080;
  chainRpcPort = 31246;
  chainOwner = "wic3EQ9UxhwPSctsVsqdK9fpqivx6bMLpZZEyVD3MYeH";
  chainSettlementMaker = "21tzoXVq7aGx61bNRTPDVn9hJhszdDA4CPcp9LYZL8ffT";
  chainSettlementTaker = "236h7pukvqi6u8ADu53erbWyLYXNyNEuB9BRNMXtVKUfZ";
  chainSettlementNative = "jesTu2BpszP8DKSoi1R5G6ggjHrsrVnboLdx6V47vkoR";

  # Presentation is deliberately independent of every Catena execution
  # environment. The proxy test never runs inference, but the gateway still
  # requires an explicit tokenizer and stop policy at its text boundary.
  # Its bytes are materialized at VM runtime below, never by a store derivation.
  testTokenizerPath = "/var/lib/hellas-gateway/test-tokenizer.json";
  testEnvironmentPath = "/var/lib/hellas-gateway/test.environment";

  responsesMock = pkgs.writeText "responses-mock.py" ''
    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer

    def response_body(request, text):
        return {
            "id": "resp_mock",
            "object": "response",
            "created_at": 0,
            "model": request["model"],
            "status": "completed",
            "output": [{
                "type": "message",
                "id": "msg_mock",
                "role": "assistant",
                "content": [{
                    "type": "output_text",
                    "text": text,
                }],
            }],
            "usage": {
                "input_tokens": 1,
                "output_tokens": 2,
                "total_tokens": 3,
            },
        }

    def sse_frame(name, data):
        encoded = json.dumps(data, separators=(",", ":"))
        return f"event: {name}\ndata: {encoded}\n\n".encode()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            assert self.path == "/v1/responses", self.path
            assert self.headers.get("authorization") == "Bearer proxy-secret"
            request = json.loads(body)
            if request.get("stream"):
                frames = [
                    sse_frame("response.output_item.added", {
                        "type": "response.output_item.added",
                        "item": {
                            "type": "message",
                            "id": "msg_mock",
                            "role": "assistant",
                            "status": "in_progress",
                            "content": [],
                        },
                    }),
                    sse_frame("response.output_text.delta", {
                        "type": "response.output_text.delta",
                        "item_id": "msg_mock",
                        "delta": "stream",
                    }),
                    sse_frame("response.output_text.delta", {
                        "type": "response.output_text.delta",
                        "item_id": "msg_mock",
                        "delta": "-proxied-ok",
                    }),
                    sse_frame("response.output_text.done", {
                        "type": "response.output_text.done",
                        "item_id": "msg_mock",
                        "text": "stream-proxied-ok",
                    }),
                    sse_frame("response.completed", {
                        "type": "response.completed",
                        "response": response_body(request, "stream-proxied-ok"),
                    }),
                ]
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.end_headers()
                for frame in frames:
                    self.wfile.write(frame)
                    self.wfile.flush()
                return

            encoded = json.dumps(response_body(request, "proxied-ok")).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *_args):
            pass

    HTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
  '';

  # The gateway's routes require this run's credential, which it draws at
  # startup, keeps in memory, and hands out in exactly one other place:
  # the environment of a command it wraps. So the caller that exercises
  # them is a wrapped child. It waits for the upstream mock, writes what
  # the gateway answered into the unit's state directory — the private
  # /tmp of a DynamicUser unit is not the test's /tmp — and then stays up,
  # so the unit and its port remain observable for the rest of the test.
  gatewayProbe = pkgs.writeShellScript "gateway-proxy-probe" ''
    set -eu
    until ${pkgs.curl}/bin/curl -sS -o /dev/null -X POST \
      -H 'content-type: application/json' \
      -H 'authorization: Bearer proxy-secret' \
      -d '{"model":"probe","input":"hi"}' \
      http://127.0.0.1:18080/v1/responses
    do
      ${pkgs.coreutils}/bin/sleep 1
    done
    ${pkgs.curl}/bin/curl -sS -X POST -H 'content-type: application/json' \
      -H "authorization: Bearer $OPENAI_API_KEY" \
      -d '{"model":"llama-local","input":"hello"}' \
      "$OPENAI_BASE_URL/responses" > response.json
    ${pkgs.curl}/bin/curl -sS -N -X POST -H 'content-type: application/json' \
      -H "authorization: Bearer $OPENAI_API_KEY" \
      -d '{"model":"llama-local","input":"hello","stream":true}' \
      "$OPENAI_BASE_URL/responses" > stream.txt
    ${pkgs.coreutils}/bin/touch probed
    exec ${pkgs.coreutils}/bin/sleep infinity
  '';

  mkBaseNode = hellasPackage: {
    networking.firewall = {
      enable = true;
      allowedUDPPorts = [ 5353 ];
      checkReversePath = false;
    };
    environment.systemPackages = with pkgs; [
      coreutils
      curl
      jq
      gnugrep
      hellasPackage
    ];
  };

  chainValidatorFollowerPrelude =
    {
      homePrefix,
      validatorLog,
      followerLog,
      allocations,
      validatorSeed,
      startPort,
      metricsPort,
      followerPartitionPrefix,
    }:
    let
      allocationArgs = lib.concatMapStringsSep " " (
        allocation: "--genesis-allocation ${allocation}"
      ) allocations;
    in
    ''
      import time

      cli = "${validatorPackage}/bin/hellas-cli"
      rpc = "ws://127.0.0.1:${toString chainRpcPort}"
      home = "HOME=${homePrefix}/client-home OTEL_SERVICE_NAME=hellas-test-client"
      validator_log = "${validatorLog}"
      follower_log = "${followerLog}"

      def parse_fields(output):
          fields = {}
          for line in output.splitlines():
              parts = line.split(" ", 1)
              if len(parts) == 2:
                  fields[parts[0]] = parts[1]
          return fields

      def latest_block():
          output = machine.succeed(f"{home} {cli} chain query --rpc {rpc} latest-block")
          fields = parse_fields(output)
          assert "height" in fields and int(fields["height"]) > 0, output
          assert "payload" in fields, output
          return fields

      def follower_height():
          output = machine.succeed(f"cat {follower_log} || true")
          heights = []
          for line in output.splitlines():
              parts = line.split()
              if len(parts) == 3 and parts[0] == "height" and parts[2] in ["Applied", "Duplicate"]:
                  heights.append(int(parts[1]))
          return max(heights) if heights else 0

      def follower_activity_events():
          output = machine.succeed(f"cat {follower_log} || true")
          return sum(1 for line in output.splitlines() if line.startswith("activity finalization "))

      def wait_for_follower_stream_ready():
          deadline = time.time() + 60
          while time.time() < deadline:
              output = machine.succeed(f"cat {follower_log} || true")
              if "activity stream subscribed" in output:
                  return
              time.sleep(1)
          follower = machine.succeed(f"cat {follower_log} || true")
          validator = machine.succeed(f"cat {validator_log} || true")
          raise Exception(
              f"follower did not subscribe to activity stream\n"
              f"follower:\n{follower}\nvalidator:\n{validator}"
          )

      start_all()
      machine.succeed(
          "mkdir -p ${homePrefix}/validator-home ${homePrefix}/client-home "
          "${homePrefix}/follower-home ${homePrefix}/follower-store"
      )
      machine.succeed(
          f"HOME=${homePrefix}/validator-home {cli} chain validator config "
          "-n 1 --seed ${toString validatorSeed} --start-port ${toString startPort} "
          "--light-client-bind 127.0.0.1:${toString chainRpcPort} "
          "--metrics-port ${toString metricsPort} ${allocationArgs} "
          "> ${homePrefix}/validator.toml"
      )
      machine.succeed(
          f"{cli} chain validator check-config --config ${homePrefix}/validator.toml | grep -Fx ok"
      )
      machine.succeed(
          f"HOME=${homePrefix}/validator-home OTEL_SERVICE_NAME=hellas-test-validator RUST_LOG=info {cli} chain validator run "
          f"--config ${homePrefix}/validator.toml "
          f"> {validator_log} 2>&1 & echo $! > ${homePrefix}/validator.pid"
      )
      try:
          machine.wait_for_open_port(${toString chainRpcPort})
      except Exception:
          print(machine.succeed(f"cat {validator_log} || true"))
          raise
      machine.succeed(
          f"HOME=${homePrefix}/follower-home OTEL_SERVICE_NAME=hellas-test-indexer RUST_LOG=info {cli} chain indexer follow "
          f"--rpc {rpc} --storage-dir ${homePrefix}/follower-store "
          "--partition-prefix ${followerPartitionPrefix} "
          f"> {follower_log} 2>&1 & echo $! > ${homePrefix}/follower.pid"
      )
      machine.wait_until_succeeds(
          f"{home} {cli} chain query --rpc {rpc} latest-block "
          f"> ${homePrefix}/latest.log && grep -Eq '^height [1-9][0-9]*$' ${homePrefix}/latest.log"
      )
      wait_for_follower_stream_ready()
    '';
in
{
  discovery-monitor = runTest {
    name = "hellas-discovery-monitor";
    nodes.machine = _: {
      imports = [ hellasModule ];
      config = lib.mkMerge [
        (mkBaseNode package)
        {
          systemd.tmpfiles.rules = [
            # The test creates its Catena program and canonical environments
            # after the VM has booted.  Keeping only an empty runtime root here
            # proves the provider did not receive a model/environment through
            # Nix evaluation or the store.
            "d /srv/hellas-content 0755 root root -"
          ];
          services.hellas = {
            enable = true;
            inherit package;
            environment.RUST_LOG = "hellas_executor=info";
            environment.OTEL_SERVICE_NAME = "hellas-test-provider";
            port = executorPort;
            openFirewall = true;
            executePolicy = "any";
            queueSize = 2;
            contentRoots = [ "/srv/hellas-content" ];
            contentIndex = "/var/lib/hellas/content-index.bin";
            gpuSessionPrograms = 3;
            gpuSessionAssetBytes = 1073741824;
            memoryMaxBytes = 1879048192;
            gpuMaxGenerationCapacity = 4096;
            gpuMaxGenerationDeviceBytes = 536870912;
            gpuCompileTimeoutSeconds = 600;
            gpuExecutionTimeoutSeconds = 900;
            fetchMaxInFlight = 2;
            fetchQueueSize = 3;
            graffiti = "e2e-discovery";
          };
          virtualisation.cores = 2;
          virtualisation.memorySize = 2048;
        }
      ];
    };
    testScript = ''
      start_all()
      machine.wait_for_unit("hellas.service")
      machine.wait_until_succeeds("test -e /var/lib/hellas/content-index.bin", timeout=30)

      # Materialize three previously unknown environments entirely at VM
      # runtime. All canonical roots are adopted from the configured content
      # root on restart. The admitted case has both its program and weights;
      # the two refusal cases independently omit one of them so quote
      # preparation cannot confuse missing content with executePolicy.
      machine.succeed(
          "systemctl stop hellas.service; "
          "install -d -m 0755 /var/lib/hellas-e2e; "
          "nonce=$(tr -d - < /proc/sys/kernel/random/uuid); "
          "printf 'not-valid-catena-%s\\n' \"$nonce\" > /srv/hellas-content/arbitrary.hex; "
          "printf 'also-not-valid-catena-%s\\n' \"$nonce\" > /var/lib/hellas-e2e/missing.hex; "
          "printf 'runtime-only-weights-%s' \"$nonce\" > /srv/hellas-content/weights.bin; "
          "printf 'missing-runtime-weights-%s' \"$nonce\" > /var/lib/hellas-e2e/missing-weights.bin; "
          "printf 'entrypoint = \"e2e_%s\"\\nstatic_objects = [\"/srv/hellas-content/weights.bin\"]\\nstatic_inputs = [{ object = 0, offset = 0, bytes = 16 }]\\nstate_bytes_per_capacity = [4]\\nvocabulary_size = 3\\nmaximum_capacity = 8\\n[generation]\\nfixed_capacity = 8\\nprefill_chunk_tokens = 2\\n' \"$nonce\" > /var/lib/hellas-e2e/environment.toml; "
          "printf 'entrypoint = \"e2e_%s\"\\nstatic_objects = [\"/var/lib/hellas-e2e/missing-weights.bin\"]\\nstatic_inputs = [{ object = 0, offset = 0, bytes = 16 }]\\nstate_bytes_per_capacity = [4]\\nvocabulary_size = 3\\nmaximum_capacity = 8\\n[generation]\\nfixed_capacity = 8\\nprefill_chunk_tokens = 2\\n' \"$nonce\" > /var/lib/hellas-e2e/missing-static.toml; "
          "printf '%s\\n' "
          "'{\"version\":\"1.0\",\"truncation\":null,\"padding\":null,\"added_tokens\":[],\"normalizer\":null,\"pre_tokenizer\":{\"type\":\"Whitespace\"},\"post_processor\":null,\"decoder\":null,\"model\":{\"type\":\"WordLevel\",\"vocab\":{\"hello\":0,\"world\":1,\"<unk>\":2},\"unk_token\":\"<unk>\"}}' "
          "> /var/lib/hellas-e2e/tokenizer.json; "
          "${package}/bin/hellas-cli environment build "
          "--program /srv/hellas-content/arbitrary.hex "
          "--settings /var/lib/hellas-e2e/environment.toml "
          "--out /srv/hellas-content/arbitrary.environment; "
          "${package}/bin/hellas-cli environment build "
          "--program /var/lib/hellas-e2e/missing.hex "
          "--settings /var/lib/hellas-e2e/environment.toml "
          "--out /srv/hellas-content/missing-program.environment; "
          "${package}/bin/hellas-cli environment build "
          "--program /srv/hellas-content/arbitrary.hex "
          "--settings /var/lib/hellas-e2e/missing-static.toml "
          "--out /srv/hellas-content/missing-static.environment; "
          "chmod 0444 /srv/hellas-content/* /var/lib/hellas-e2e/*; "
          "chmod 0555 /srv/hellas-content; "
          "systemctl start hellas.service"
      )
      machine.wait_for_unit("hellas.service")
      machine.succeed("test -s /var/lib/hellas/content-index.bin")

      node_id = machine.succeed(
          "HOME=/var/lib/hellas ${package}/bin/hellas-cli identity show-node-id"
      ).strip()
      provider = machine.succeed(
          "HOME=/var/lib/hellas ${package}/bin/hellas-cli identity show-enrollment-id"
      ).strip()
      client = (
          "HOME=/var/lib/hellas-e2e OTEL_SERVICE_NAME=hellas-test-client ${package}/bin/hellas-cli "
          "--identity /var/lib/hellas-e2e/client.identity --software-root llm "
          f"{node_id} --node-addr 127.0.0.1:${toString executorPort} "
          f"--provider {provider} "
          "--tokenizer /var/lib/hellas-e2e/tokenizer.json "
          "--prompt hello --max-new-tokens 1"
      )

      missing = machine.succeed(
          "set +e; "
          f"{client} --environment /srv/hellas-content/missing-program.environment "
          "> /var/lib/hellas-e2e/missing-program.log 2>&1; "
          "status=$?; test \"$status\" -ne 0; "
          "cat /var/lib/hellas-e2e/missing-program.log"
      )
      print(missing)
      assert "is not locally available" in missing
      assert "policy denied" not in missing
      assert "execute policy denied" not in missing

      missing_static = machine.succeed(
          "set +e; "
          f"{client} --environment /srv/hellas-content/missing-static.environment "
          "> /var/lib/hellas-e2e/missing-static.log 2>&1; "
          "status=$?; test \"$status\" -ne 0; "
          "cat /var/lib/hellas-e2e/missing-static.log"
      )
      print(missing_static)
      assert "is not locally available" in missing_static
      assert "policy denied" not in missing_static
      assert "execute policy denied" not in missing_static

      admitted = machine.succeed(
          "set +e; "
          f"{client} --environment /srv/hellas-content/arbitrary.environment "
          "> /var/lib/hellas-e2e/admitted.log 2>&1; "
          "status=$?; test \"$status\" -ne 0; "
          "cat /var/lib/hellas-e2e/admitted.log"
      )
      print(admitted)
      assert (
          "did not compile" in admitted
          or "GPU runtime is unavailable" in admitted
      ), admitted
      assert "policy denied" not in admitted
      assert "is not locally available" not in admitted

      provider_log = machine.succeed("journalctl -u hellas.service --no-pager")
      print(provider_log)
      assert "quoted causal-LM evaluate execution" in provider_log
      assert "accepted evaluate execution" in provider_log
      assert (
          "Catena program compilation failed" in provider_log
          or "failed to start Catena GPU asset owner" in provider_log
      ), provider_log

      unit = machine.succeed(
          "systemctl show hellas.service "
          "--property=Environment --property=ExecStart --property=LimitMEMLOCK "
          "--property=MemoryMax --property=MemorySwapMax --property=OOMPolicy"
      )
      assert "--execute-policy any" in unit
      assert "--content-root /srv/hellas-content" in unit
      assert "--content-index /var/lib/hellas/content-index.bin" in unit
      assert "--gpu-session-programs 3" in unit
      assert "--gpu-session-asset-bytes 1073741824" in unit
      assert "LimitMEMLOCK=infinity" in unit
      assert "MemoryMax=1879048192" in unit
      assert "MemorySwapMax=0" in unit
      assert "OOMPolicy=kill" in unit
      assert "--gpu-max-generation-capacity 4096" in unit
      assert "--gpu-max-generation-device-bytes 536870912" in unit
      assert "--gpu-compile-timeout-secs 600" in unit
      assert "--gpu-execution-timeout-secs 900" in unit
      assert "TMPDIR=/run/hellas" in unit
      machine.succeed(
          "test \"$(cat /sys/fs/cgroup/system.slice/hellas.service/memory.oom.group)\" = 1"
      )
      machine.succeed(
          "test \"$(cat /sys/fs/cgroup/system.slice/hellas.service/memory.swap.max)\" = 0"
      )

      try:
          machine.wait_until_succeeds(
              "${package}/bin/hellas-cli monitor --timeout-secs 5 > /tmp/hellas-monitor.log 2>&1"
              " && grep -q 'event=discovered service=node' /tmp/hellas-monitor.log"
              " && grep -q 'event=node-info' /tmp/hellas-monitor.log",
              timeout=30,
          )
      finally:
          monitor_output = machine.succeed("cat /tmp/hellas-monitor.log")
          print(monitor_output)
      assert "graffiti=e2e-discovery" in monitor_output
    '';
  };

  gateway-proxy-responses = runTest {
    name = "hellas-gateway-proxy-responses";
    nodes.gateway = _: {
      imports = [ hellasModule ];
      config = lib.mkMerge [
        (mkBaseNode package)
        {
          environment.systemPackages = [ pkgs.python3 ];
          services.hellas = {
            inherit package;
            environment.OPENAI_API_KEY = "proxy-secret";
            environment.OTEL_SERVICE_NAME = "hellas-test-gateway";
            gateway = {
              enable = true;
              port = gatewayPort;
              causalLmEnvironment = testEnvironmentPath;
              model = "smollm2-135m";
              tokenizer = testTokenizerPath;
              stopTokenIds = [ 2 ];
              responsesBackend = "proxy";
              responsesProxyUrl = "http://127.0.0.1:18080/v1/responses";
              responsesProxyApiKeyEnv = "OPENAI_API_KEY";
              # No nodeId, no verifyNodeId: this gateway dials no provider,
              # so it needs no provider trust anchor to start.
              extraArgs = [
                "--wrap"
                "${gatewayProbe}"
              ];
            };
          };
          systemd.services.hellas-gateway.preStart = ''
            cat > ${testTokenizerPath} <<'EOF'
            {
              "version": "1.0",
              "truncation": null,
              "padding": null,
              "added_tokens": [],
              "normalizer": null,
              "pre_tokenizer": { "type": "Whitespace" },
              "post_processor": null,
              "decoder": null,
              "model": {
                "type": "WordLevel",
                "vocab": { "hello": 0, "world": 1, "<unk>": 2 },
                "unk_token": "<unk>"
              }
            }
            EOF
            printf 'test Catena source\n' > /var/lib/hellas-gateway/test.hex
            cat > /var/lib/hellas-gateway/test.toml <<'EOF'
            entrypoint = "test"
            state_bytes_per_capacity = [4]
            vocabulary_size = 3
            maximum_capacity = 8
            [generation]
            fixed_capacity = 8
            prefill_chunk_tokens = 2
            EOF
            ${package}/bin/hellas-cli environment build \
              --program /var/lib/hellas-gateway/test.hex \
              --settings /var/lib/hellas-gateway/test.toml \
              --out ${testEnvironmentPath}
          '';
        }
      ];
    };
    testScript = ''
      start_all()

      gateway.succeed("python3 ${responsesMock} >/tmp/responses_mock.log 2>&1 &")
      gateway.wait_until_succeeds("curl -sS -o /dev/null -X POST -H 'content-type: application/json' -H 'authorization: Bearer proxy-secret' -d '{\"model\":\"probe\",\"input\":\"hi\"}' http://127.0.0.1:18080/v1/responses")
      gateway.wait_for_unit("hellas-gateway.service")
      unit = gateway.succeed("systemctl show hellas-gateway.service --property=Environment --property=ExecStart")
      assert "--environment ${testEnvironmentPath}" in unit
      assert "--model smollm2-135m" in unit
      assert "--tokenizer ${testTokenizerPath}" in unit
      assert "TMPDIR=/var/cache/hellas-gateway" not in unit
      gateway.wait_for_open_port(${toString gatewayPort})
      gateway.wait_until_succeeds("test -e /var/lib/hellas-gateway/probed")

      response = gateway.succeed("cat /var/lib/hellas-gateway/response.json")
      print(response)
      assert "proxied-ok" in response
      stream = gateway.succeed("cat /var/lib/hellas-gateway/stream.txt")
      print(stream)
      assert "stream-proxied-ok" in stream
      assert "response.output_text.delta" in stream
      assert '"output_index":0' in stream
      assert '"content_index":0' in stream

      # The same route, reached without the run's credential, is refused
      # before the proxy is asked for anything.
      refused = gateway.succeed("curl -sS -X POST -H 'content-type: application/json' -d '{\"model\":\"llama-local\",\"input\":\"hello\"}' http://127.0.0.1:${toString gatewayPort}/v1/responses")
      print(refused)
      assert "per-run credential" in refused
      assert "proxied-ok" not in refused
    '';
  };

  chain-validator-follower = runTest {
    name = "hellas-chain-validator-follower";
    nodes.machine = _: {
      config = lib.mkMerge [
        (mkBaseNode validatorPackage)
        {
          virtualisation.cores = 2;
          virtualisation.memorySize = 2048;
        }
      ];
    };
    testScript = ''
      ${chainValidatorFollowerPrelude {
        homePrefix = "/tmp/chain-e2e";
        validatorLog = "/tmp/chain-e2e/validator.log";
        followerLog = "/tmp/chain-e2e/follower.log";
        allocations = [ "${chainOwner}:424242" ];
        validatorSeed = 7;
        startPort = 31200;
        metricsPort = 39200;
        followerPartitionPrefix = "chain-e2e-follower";
      }}
      owner = "${chainOwner}"

      def wait_for_follower_stream(baseline, baseline_events):
          deadline = time.time() + 60
          while time.time() < deadline:
              remote = int(latest_block()["height"])
              local = follower_height()
              events = follower_activity_events()
              if remote > baseline and local > baseline and events > baseline_events:
                  return local
              time.sleep(1)
          follower = machine.succeed(f"cat {follower_log} || true")
          validator = machine.succeed(f"cat {validator_log} || true")
          raise Exception(f"follower did not advance past {baseline}: remote={remote} local={local} events={events}\nfollower:\n{follower}\nvalidator:\n{validator}")

      baseline = follower_height()
      baseline_events = follower_activity_events()
      advanced = wait_for_follower_stream(baseline, baseline_events)
      print(f"follower advanced from {baseline} to {advanced}")

      latest = latest_block()
      height = int(latest["height"])
      payload = latest["payload"]

      by_height = machine.succeed(f"{home} {cli} chain query --rpc {rpc} finalized-block --height {height}")
      assert f"height {height}" in by_height.splitlines(), by_height
      assert f"payload {payload}" in by_height.splitlines(), by_height
      assert any(line.startswith("block ") for line in by_height.splitlines()), by_height

      by_payload = machine.succeed(f"{home} {cli} chain query --rpc {rpc} finalized-block --payload {payload}")
      assert f"height {height}" in by_payload.splitlines(), by_payload
      assert f"payload {payload}" in by_payload.splitlines(), by_payload

      finalization = machine.succeed(f"{home} {cli} chain query --rpc {rpc} finalization --payload {payload}").strip()
      assert len(finalization) > 64 and all(c in "0123456789abcdef" for c in finalization), finalization

      validators = machine.succeed(f"{home} {cli} chain query --rpc {rpc} validators")
      assert validators.strip(), validators

      coins = machine.succeed(f"{home} {cli} chain query --rpc {rpc} coins-by-owner --owner {owner}")
      coin_lines = [line for line in coins.splitlines() if line.endswith(" 424242")]
      assert len(coin_lines) == 1, coins

    '';
  };

  chain-edge-settlement = runTest {
    name = "hellas-chain-edge-settlement";
    nodes.machine = _: {
      config = lib.mkMerge [
        (mkBaseNode validatorPackage)
        {
          virtualisation.cores = 2;
          virtualisation.memorySize = 2048;
        }
      ];
    };
    testScript = ''
      ${chainValidatorFollowerPrelude {
        homePrefix = "/tmp/chain-settlement";
        validatorLog = "/tmp/chain-settlement/validator.log";
        followerLog = "/tmp/chain-settlement/follower.log";
        allocations = [
          "${chainSettlementMaker}:100"
          "${chainSettlementTaker}:100"
        ];
        validatorSeed = 17;
        startPort = 31300;
        metricsPort = 39300;
        followerPartitionPrefix = "chain-settlement-follower";
      }}
      import re

      maker = "${chainSettlementMaker}"
      taker = "${chainSettlementTaker}"
      native = "${chainSettlementNative}"

      def coin_map(owner):
          output = machine.succeed(f"{home} {cli} chain query --rpc {rpc} coins-by-owner --owner {owner}")
          coins = {}
          for line in output.splitlines():
              parts = line.split()
              if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]) and parts[1].isdigit():
                  coins[parts[0]] = int(parts[1])
          return coins, output

      def wait_coin(owner, value):
          deadline = time.time() + 90
          while time.time() < deadline:
              coins, output = coin_map(owner)
              matches = [object_id for object_id, amount in coins.items() if amount == value]
              if len(matches) == 1:
                  return matches[0]
              time.sleep(1)
          raise Exception(f"owner {owner} did not acquire one {value}-value coin:\n{output}")

      def edge_output(edge_id):
          deadline = time.time() + 30
          while time.time() < deadline:
              payload = latest_block()["payload"]
              status, output = machine.execute(
                  f"{home} {cli} chain query --rpc {rpc} edge --object-id {edge_id} --payload {payload}"
              )
              if status == 0:
                  return output
              time.sleep(1)
          raise Exception(f"edge query did not reach an indexed snapshot:\n{output}")

      def wait_edge(edge_id, present):
          try:
              deadline = time.time() + 90
              while time.time() < deadline:
                  output = edge_output(edge_id)
                  found = any(line.startswith("value ") for line in output.splitlines())
                  absent = "none" in output.splitlines()
                  if (present and found) or (not present and absent):
                      return int(latest_block()["height"])
                  time.sleep(1)
              raise Exception(f"edge {edge_id} presence did not become {present}:\n{output}")
          except Exception as err:
              procs = machine.succeed("ps aux | grep -i hellas | grep -v grep || true")
              follower = machine.succeed(f"tail -40 {follower_log} || true")
              dmesg = machine.succeed("dmesg | tail -15 || true")
              validator = machine.succeed(f"tail -60 {validator_log} || true")
              raise Exception(
                  f"wait_edge({edge_id}, {present}) failed: {err}\n"
                  f"procs:\n{procs}\nfollower:\n{follower}\ndmesg:\n{dmesg}\nvalidator:\n{validator}"
              ) from err

      def follower_progress():
          return follower_height(), follower_activity_events()

      def wait_follower(baseline):
          deadline = time.time() + 90
          while time.time() < deadline:
              height = follower_height()
              events = follower_activity_events()
              if height > baseline[0] and events > baseline[1]:
                  return
              time.sleep(1)
          follower = machine.succeed(f"cat {follower_log} || true")
          validator = machine.succeed(f"cat {validator_log} || true")
          raise Exception(
              f"follower did not advance after transition from height {baseline[0]} "
              f"and {baseline[1]} activity events\n"
              f"follower:\n{follower}\nvalidator:\n{validator}"
          )

      machine.succeed(
          "printf '0000000000000000000000000000000000000000000000000000000000000001\\n' "
          "> /tmp/chain-settlement/maker.key"
      )
      machine.succeed(
          "printf '0000000000000000000000000000000000000000000000000000000000000002\\n' "
          "> /tmp/chain-settlement/taker.key"
      )
      machine.succeed(
          "printf '0000000000000000000000000000000000000000000000000000000000000001\\n' "
          "> /tmp/chain-settlement/native.key"
      )
      # Scenario A: two genesis P-256 owners open with WebAuthn and mutually close.
      maker_genesis = wait_coin(maker, 100)
      taker_genesis = wait_coin(taker, 100)
      height = int(latest_block()["height"])
      baseline = follower_progress()
      opened = machine.succeed(
          f"{home} {cli} chain open --rpc {rpc} "
          "--maker-key /tmp/chain-settlement/maker.key --maker-auth webauthn "
          "--taker-key /tmp/chain-settlement/taker.key --taker-auth webauthn "
          f"--maker-funding {maker_genesis} --taker-funding {taker_genesis} "
          f"--protocol 1 --timeout {height + 1000000} "
          f"--timeout-payout {maker}:100 --timeout-payout {taker}:100"
      )
      edge_a = parse_fields(opened)["edge_id"]
      wait_edge(edge_a, True)
      wait_follower(baseline)
      edge_state = edge_output(edge_a)
      assert f"maker {maker}" in edge_state.splitlines(), edge_state
      assert f"taker {taker}" in edge_state.splitlines(), edge_state

      baseline = follower_progress()
      machine.succeed(
          f"{home} {cli} chain close --rpc {rpc} --edge-id {edge_a} --kind mutual "
          f"--payout {maker}:80 --payout {taker}:70 --payout {native}:50 "
          "--maker-key /tmp/chain-settlement/maker.key --maker-auth webauthn "
          "--taker-key /tmp/chain-settlement/taker.key --taker-auth webauthn"
      )
      wait_edge(edge_a, False)
      wait_follower(baseline)
      maker_coin = wait_coin(maker, 80)
      assert wait_coin(taker, 70)
      native_coin = wait_coin(native, 50)

      # Scenario B: the untagged k1 payout funds an all-native edge and close.
      height = int(latest_block()["height"])
      baseline = follower_progress()
      opened = machine.succeed(
          f"{home} {cli} chain open --rpc {rpc} "
          "--maker-key /tmp/chain-settlement/native.key --maker-auth native "
          "--taker-key /tmp/chain-settlement/native.key --taker-auth native "
          f"--maker-funding {native_coin} --protocol 2 --timeout {height + 1000000} "
          f"--timeout-payout {native}:50"
      )
      edge_b = parse_fields(opened)["edge_id"]
      wait_edge(edge_b, True)
      wait_follower(baseline)

      baseline = follower_progress()
      machine.succeed(
          f"{home} {cli} chain close --rpc {rpc} --edge-id {edge_b} --kind mutual "
          f"--payout {native}:50 "
          "--maker-key /tmp/chain-settlement/native.key --maker-auth native "
          "--taker-key /tmp/chain-settlement/native.key --taker-auth native"
      )
      wait_edge(edge_b, False)
      wait_follower(baseline)
      assert wait_coin(native, 50)

      # Scenario C: canonical Terms are persisted at Open and revealed at timeout.
      height = int(latest_block()["height"])
      timeout = height + 2000
      baseline = follower_progress()
      opened = machine.succeed(
          f"{home} {cli} chain open --rpc {rpc} "
          "--maker-key /tmp/chain-settlement/maker.key --maker-auth webauthn "
          "--taker-key /tmp/chain-settlement/taker.key --taker-auth webauthn "
          f"--maker-funding {maker_coin} --protocol 3 --timeout {timeout} "
          f"--timeout-payout {maker}:80 --terms-out /tmp/chain-settlement/timeout.terms"
      )
      edge_c = parse_fields(opened)["edge_id"]
      wait_edge(edge_c, True)
      wait_follower(baseline)
      while int(latest_block()["height"]) < timeout:
          time.sleep(1)

      baseline = follower_progress()
      machine.succeed(
          f"{home} {cli} chain close --rpc {rpc} --edge-id {edge_c} --kind timeout "
          f"--payout {maker}:80 --terms-file /tmp/chain-settlement/timeout.terms"
      )
      wait_edge(edge_c, False)
      wait_follower(baseline)
      assert wait_coin(maker, 80)

    '';
  };
}
