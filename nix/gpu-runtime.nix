{ pkgs, backend }:
let
  inherit (pkgs) lib;
  cuda = backend == "cuda";
  toolkit = if cuda then pkgs.hellasLib.cudaToolkit else pkgs.hellasLib.rocmToolkit;
  compiler = pkgs.cudaPackages.backendStdenv.cc;
  packages = [
    toolkit
    pkgs.coreutils
    pkgs.binutils
    pkgs.bash
  ]
  ++ lib.optional cuda compiler;
  environment = {
    PATH = lib.makeBinPath packages;
    # ROCm's lib/ carries its own glibc; find HIP through ROCM_PATH/HIP_PATH
    # without replacing the executable's loader-matched libc.
    LD_LIBRARY_PATH = "${lib.optionalString cuda "${toolkit}/lib:"}/usr/local/nvidia/lib64:/usr/local/nvidia/lib:/run/opengl-driver/lib";
  }
  // (
    if cuda then
      {
        CUDA_PATH = "${toolkit}";
        NVCC_CCBIN = "${compiler}/bin/c++";
        NVIDIA_VISIBLE_DEVICES = "all";
        NVIDIA_DRIVER_CAPABILITIES = "compute,utility";
      }
    else
      {
        ROCM_PATH = "${toolkit}";
        HIP_PATH = "${toolkit}";
        HIP_CLANG_PATH = "${toolkit}/bin";
        DEVICE_LIB_PATH = "${toolkit}/amdgcn/bitcode";
        HIP_FLAGS = "--rocm-path=${toolkit} --rocm-device-lib-path=${toolkit}/amdgcn/bitcode";
      }
  );
in
assert builtins.elem backend [
  "cuda"
  "hip"
];
{
  inherit packages environment;
  wrap =
    cli:
    pkgs.runCommand "hellas-${backend}"
      {
        nativeBuildInputs = [ pkgs.makeWrapper ];
        meta.mainProgram = "hellas";
      }
      ''
        mkdir -p "$out/bin"
        makeWrapper ${lib.getExe cli} "$out/bin/hellas" ${
          lib.concatStringsSep " " (
            lib.mapAttrsToList (
              name: value:
              (
                if
                  builtins.elem name [
                    "PATH"
                    "LD_LIBRARY_PATH"
                  ]
                then
                  "--prefix ${name} : "
                else
                  "--set ${name} "
              )
              + lib.escapeShellArg value
            ) environment
          )
        }
      '';
}
