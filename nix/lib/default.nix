{ pkgs, nix-strix-halo }:
let
  rocm = import ../rocm.nix { inherit pkgs nix-strix-halo; };
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

  # One coherent ROCm prefix for hipcc, runtime loading, and device bitcode.
  # Generated Catena sources and shared objects are runtime data elsewhere;
  # this derivation contains only the provider toolchain.
  rocmToolkit = pkgs.symlinkJoin {
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
  cudaToolkit = pkgs.symlinkJoin {
    name = "hellas-cuda-toolkit";
    nativeBuildInputs = [ pkgs.makeWrapper ];
    postBuild = ''
      wrapProgram "$out/bin/nvcc" \
        --add-flags "-I$out/include -L$out/lib" \
        --set-default NVCC_CCBIN "${pkgs.cudaPackages.backendStdenv.cc}/bin/c++"
    '';
    paths = with pkgs.cudaPackages; [
      cuda_nvcc
      cuda_cudart
      cccl
    ];
  };
}
