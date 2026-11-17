final: prev: {
  hellasLib = import ./lib { pkgs = final; };

  opentelemetry-collector-contrib = prev.opentelemetry-collector-contrib.overrideAttrs (old: {
    postConfigure = (old.postConfigure or "") + ''
      patchModule() {
        go mod download "$1"
        module_source=$(go list -m -f '{{.Dir}}' "$1")
        chmod -R u+w "$module_source"
        patch --directory="$module_source" -p1 < "$2"
      }
      # Enable Swiss's runtime bindings on Go 1.27 (upstream aa852fb).
      patchModule github.com/cockroachdb/swiss ${
        prev.fetchpatch {
          url = "https://github.com/cockroachdb/swiss/commit/aa852fb3c14e2d34704a42ee989711108b6f4200.patch";
          includes = [ "runtime_go1.20.go" ];
          hash = "sha256-tzCOFoHDnjMQ6Zk8687L5NCZFRHcksKhBg6m8SjDcmw=";
        }
      }
      # Avoid JOSE's zero-hash registration panic on Go 1.27 (upstream #58).
      patchModule github.com/SermoDigital/jose ${
        prev.fetchpatch {
          url = "https://github.com/SermoDigital/jose/commit/431ac3af3ad301bda630a20d63a3a0da1aa419a8.patch";
          hash = "sha256-6H0eNSw3y0WcW8nHuAVniRjERA5DM3I4s+9hBGltB4A=";
        }
      }
    '';
  });
}
