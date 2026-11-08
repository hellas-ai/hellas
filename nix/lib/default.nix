{ pkgs }:
let
  # One coherent ROCm prefix for hipcc, runtime loading, and device bitcode,
  # assembled from a ROCm package set. Generated Catena sources and shared
  # objects are runtime data elsewhere; this derivation contains only the
  # provider toolchain.
  mkRocmToolkit =
    rocm:
    pkgs.symlinkJoin {
      name = "hellas-rocm-toolkit";
      nativeBuildInputs = [ pkgs.makeWrapper ];
      postBuild = ''
        wrapProgram "$out/bin/hipcc" \
          --add-flags "--rocm-path=$out --rocm-device-lib-path=${rocm.rocm-device-libs}/amdgcn/bitcode -I$out/include -L$out/lib" \
          --set-default HIP_PATH "$out" \
          --set-default ROCM_PATH "$out" \
          --set-default HIP_CLANG_PATH "${rocm.clang}/bin"
      '';
      paths = [
        rocm.clang
        rocm.clr
        rocm.hip-common
        rocm.hipcc
        rocm.rocm-core
        rocm.rocm-device-libs
        rocm.rocm-runtime
      ];
    };
in
{
  apiFlavor = {
    anthropic = "anthropic-messages";
    openai = "openai-completions";
  };
  # Canonical executor UDP port. Matches `DEFAULT_PORT` in
  # `crates/cli/src/commands/serve/node.rs` and the `31145/udp` exposed by
  # the docker images.
  executorPort = 31145;
  # Default state directory for the Hellas serve daemon. Used by the NixOS
  # module as HOME / WorkingDirectory, and as the base for any documented
  # path examples.
  defaultStateDir = "/var/lib/hellas";

  inherit mkRocmToolkit;
  rocmToolkit = mkRocmToolkit pkgs.rocmPackages;
  cudaToolkit = pkgs.symlinkJoin {
    name = "hellas-cuda-toolkit";
    nativeBuildInputs = [ pkgs.makeWrapper ];
    postBuild = ''
      wrapProgram "$out/bin/nvcc" \
        --add-flags "-I$out/include -L$out/lib" \
        --set-default NVCC_CCBIN "${pkgs.cudaPackages.backendStdenv.cc}/bin/c++"
      # CUDA splits its compiler headers into cuda_crt. Exercise the assembled
      # prefix without a GPU so a missing component cannot reach a runtime image.
      cat > cuda-smoke.cu <<'EOF'
      #include <cuda_runtime.h>
      #include <cuda_bf16.h>
      extern "C" __global__ void smoke(__nv_bfloat16 *out) {
        out[0] = __float2bfloat16(42.0f);
      }
      EOF
      "$out/bin/nvcc" --std=c++17 --shared -Xcompiler=-fPIC -arch=sm_89 \
        cuda-smoke.cu -o cuda-smoke.so
    '';
    paths = with pkgs.cudaPackages; [
      cuda_nvcc
      cuda_crt
      cuda_cudart
      cccl
    ];
  };
}
