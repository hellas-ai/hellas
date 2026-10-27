{
  pkgs,
  hellasLib,
  rocminfo,
}:
{
  smoke =
    pkgs.runCommand "hellas-gpu-smoke"
      {
        requiredSystemFeatures = [ "gfx1151" ];
        nativeBuildInputs = [
          hellasLib.rocmToolkit
          rocminfo
        ];
        ROCM_PATH = "${hellasLib.rocmToolkit}";
      }
      ''
        unset LD_LIBRARY_PATH
        if ! rocminfo > device.txt 2>&1; then
          cat device.txt
          exit 1
        fi
        cat device.txt
        if ! grep -E 'Name:.*gfx1151' device.txt; then
          exit 1
        fi
        hipcc --offload-arch=gfx1151 -x hip -shared -fPIC -O2 \
          ${./gpu-smoke.hip} -o smoke.so
        # TheRock hipcc can exit successfully after a compiler crash.
        test -s smoke.so
        $CXX ${./gpu-smoke.cc} -ldl -o smoke
        ./smoke "$PWD/smoke.so"
        mkdir -p "$out"
        echo 'gfx1151: HIP shared library loaded and all 256 sums matched' > "$out/result"
      '';
}
