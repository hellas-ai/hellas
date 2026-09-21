{
  self,
  hellas ? import ./hellas.nix { inherit self; },
}:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.hellas;
in
{
  # Shared CLI configuration for nix-darwin. The per-user serve daemon is
  # supplied by the Home Manager module's existing launchd integration.
  options.programs.hellas = hellas.commonOptions {
    inherit lib;
    inherit (cfg) otel;
    package = (hellas.normalCliPackage pkgs).override { otel = cfg.otel.enable; };
    packageDescription = "Hellas network CLI. The shared otel settings select a telemetry-enabled build when configured.";
  };
  config = lib.mkIf cfg.enable {
    environment.systemPackages = [
      (hellas.withEnvironment {
        inherit lib pkgs;
        inherit (cfg) package;
        environment =
          hellas.mkOtelEnv {
            inherit lib;
            inherit (cfg) otel;
          }
          // cfg.environment;
      })
    ];
  };
}
