{
  pkgs,
  rustToolchain,
  cli,
  backend ? "network",
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
        cp "${cli}/bin/hellas" "$out/bin/hellas"
        chmod u+w "$out/bin/hellas"
        remove-references-to -t ${rustToolchain} "$out/bin/hellas"
        chmod 0555 "$out/bin/hellas"
      '';

  gpu = backend != "network";
  cuda = backend == "cuda";
  gpuRuntime = import ./gpu-runtime.nix { inherit pkgs backend; };
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
      exec ${runtime}/bin/hellas "$@"
    ''
  );
  image = pkgs.dockerTools.streamLayeredImage {
    name = imageRepository;
    tag = backend;
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
    ++ pkgs.lib.optionals gpu gpuRuntime.packages;
    config = {
      Entrypoint = [ (if cuda then "${entrypoint}" else "${runtime}/bin/hellas") ];
      Cmd = [
        "serve"
        "--port"
        "31145"
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
        "HELLAS_HOME=/var/lib/hellas/.hellas"
        "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        "NIX_SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      ]
      ++ pkgs.lib.optionals gpu (
        pkgs.lib.mapAttrsToList (name: value: "${name}=${value}") gpuRuntime.environment
      );
    };
  };

in
{
  inherit image;
}
