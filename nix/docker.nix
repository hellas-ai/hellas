{
  pkgs,
  rustToolchain,
  cli,
  backend ? "network",
  agent ? null,
  revision ? "unknown",
}:
let
  imageRepository = "ghcr.io/hellas-ai/hellas";

  runtime =
    pkgs.runCommand "hellas-cli-${backend}-runtime"
      {
        nativeBuildInputs = [ pkgs.removeReferencesTo ];
      }
      ''
        mkdir -p "$out/bin"
        cp "${cli}/bin/hellas-cli" "$out/bin/hellas-cli"
        chmod u+w "$out/bin/hellas-cli"
        remove-references-to -t ${rustToolchain} "$out/bin/hellas-cli"
        chmod 0555 "$out/bin/hellas-cli"
      '';

  agentRuntime =
    pkgs.runCommand "hellas-agent-runtime"
      {
        nativeBuildInputs = [ pkgs.removeReferencesTo ];
      }
      ''
        mkdir -p "$out/bin"
        cp "${agent}/bin/hellas-agent" "$out/bin/hellas-agent"
        chmod u+w "$out/bin/hellas-agent"
        remove-references-to -t ${rustToolchain} "$out/bin/hellas-agent"
        chmod 0555 "$out/bin/hellas-agent"
      '';
  originalEntrypoint = [
    (if cuda then "${entrypoint}" else "${runtime}/bin/hellas-cli")
    "serve"
  ]
  ++ pkgs.lib.optionals gpu [
    "--gpu-backend"
    backend
  ];
  launcher = pkgs.writeText "hellas-${backend}-launcher.json" (builtins.toJSON originalEntrypoint);
  imageTag = if agent == null then backend else "cloud-${backend}";

  gpu = backend != "network";
  cuda = backend == "cuda";
  toolkit = if cuda then pkgs.hellasLib.cudaToolkit else pkgs.hellasLib.rocmToolkit;
  compiler = pkgs.cudaPackages.backendStdenv.cc;
  entrypoint = pkgs.writeShellScript "hellas-${backend}-entrypoint" (
    pkgs.lib.optionalString cuda ''
      # CDI can inject the driver at a host-specific path, including /nix/store.
      # Read the container cache explicitly: Nix glibc does not search it.
      driver=$(${pkgs.glibc.bin}/bin/ldconfig -C /etc/ld.so.cache -p 2>/dev/null | ${pkgs.gawk}/bin/awk '$1 == "libcuda.so.1" { print $NF; exit }')
      if [ -n "$driver" ]; then
        export LD_LIBRARY_PATH="''${driver%/*}:''${LD_LIBRARY_PATH:-}"
      fi
    ''
    + ''
      exec ${runtime}/bin/hellas-cli "$@"
    ''
  );
  image = pkgs.dockerTools.streamLayeredImage {
    name = imageRepository;
    tag = imageTag;
    extraCommands = pkgs.lib.optionalString gpu ''
      mkdir -m 1777 -p tmp
    '';
    contents = [
      runtime
      pkgs.cacert
      pkgs.iana-etc
      pkgs.stdenv.cc.cc.lib
      pkgs.glibc
    ]
    ++ pkgs.lib.optionals gpu [
      toolkit
      pkgs.coreutils
      pkgs.binutils
      pkgs.bash
    ]
    ++ pkgs.lib.optional cuda compiler
    ++ pkgs.lib.optional (agent != null) agentRuntime;
    config = {
      Entrypoint =
        if agent == null then
          originalEntrypoint
        else
          [
            "${agentRuntime}/bin/hellas-agent"
            "--cli"
            "${runtime}/bin/hellas-cli"
            "--launcher"
            "${launcher}"
          ];
      Labels = {
        "org.opencontainers.image.source" = "https://github.com/hellas-ai/hellas";
        "org.opencontainers.image.revision" = revision;
      };
      WorkingDir = "/var/lib/hellas";
      Volumes."/var/lib/hellas" = { };
      ExposedPorts."31145/udp" = { };
      Env = [
        "HOME=/var/lib/hellas"
        "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        "NIX_SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      ]
      ++ pkgs.lib.optionals gpu [
        "PATH=${
          pkgs.lib.makeBinPath (
            [
              toolkit
              pkgs.coreutils
              pkgs.binutils
              pkgs.bash
            ]
            ++ pkgs.lib.optional cuda compiler
          )
        }"
        "LD_LIBRARY_PATH=${toolkit}/lib:/usr/local/nvidia/lib64:/usr/local/nvidia/lib:/run/opengl-driver/lib"
      ]
      ++ (
        if cuda then
          [
            "CUDA_PATH=${toolkit}"
            "NVCC_CCBIN=${compiler}/bin/c++"
            "NVIDIA_VISIBLE_DEVICES=all"
            "NVIDIA_DRIVER_CAPABILITIES=compute,utility"
          ]
        else
          pkgs.lib.optionals gpu [
            "ROCM_PATH=${toolkit}"
            "HIP_PATH=${toolkit}"
            "HIP_CLANG_PATH=${toolkit}/bin"
            "DEVICE_LIB_PATH=${toolkit}/amdgcn/bitcode"
            "HIP_FLAGS=--rocm-path=${toolkit} --rocm-device-lib-path=${toolkit}/amdgcn/bitcode"
          ]
      );
    };
  };

  push = pkgs.writeShellApplication {
    name = "docker-push";
    runtimeInputs = [ pkgs.skopeo ];
    text = ''
      ${image} | skopeo copy docker-archive:/dev/stdin "docker://${imageRepository}:${imageTag}" "$@"
    '';
  };
in
{
  inherit image push;
}
