final: prev: {
  hellasLib = import ./lib { pkgs = final; };

  # Keep nixpkgs' full distribution and locked modules; backport its two Go
  # 1.27 compatibility fixes until nixpkgs updates the collector (PR #581121).
  opentelemetry-collector-contrib = prev.opentelemetry-collector-contrib.overrideAttrs (old: {
    postConfigure = (old.postConfigure or "") + ''
      patchModule() {
        go mod download "$1"
        module_source=$(go list -m -f '{{.Dir}}' "$1")
        chmod -R u+w "$module_source"
        patch --directory="$module_source" -p1 < "$2"
      }
      # Upstream's tested Go 1.27 runtime guard; no untested_go_version flag.
      patchModule github.com/cockroachdb/swiss ${
        prev.fetchpatch {
          url = "https://github.com/cockroachdb/swiss/commit/aa852fb3c14e2d34704a42ee989711108b6f4200.patch";
          includes = [ "runtime_go1.20.go" ];
          hash = "sha256-tzCOFoHDnjMQ6Zk8687L5NCZFRHcksKhBg6m8SjDcmw=";
        }
      }
      # Go 1.27 rejects registering hash zero at startup: upstream jose PR #58.
      patchModule github.com/SermoDigital/jose ${
        prev.fetchpatch {
          url = "https://github.com/SermoDigital/jose/commit/431ac3af3ad301bda630a20d63a3a0da1aa419a8.patch";
          hash = "sha256-6H0eNSw3y0WcW8nHuAVniRjERA5DM3I4s+9hBGltB4A=";
        }
      }
    '';
    postCheck = (old.postCheck or "") + ''
      go test github.com/SermoDigital/jose/{crypto,jws}
      # Run Swiss correctness tests without its optional benchmark dependencies.
      swiss_source=$(go list -m -f '{{.Dir}}' github.com/cockroachdb/swiss)
      mapfile -t swiss_files < <(go list -tags=swiss_invariants -f '{{range .GoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}' github.com/cockroachdb/swiss | sed '/^$/d')
      go test -tags=swiss_invariants "''${swiss_files[@]}" "$swiss_source/map_test.go"
    '';
  });
}
