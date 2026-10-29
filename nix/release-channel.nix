{
  pkgs,
  self,
  component,
  jobs,
}:
let
  revision = self.rev or self.dirtyRev or "unknown";
  manifest = pkgs.writeText "release.json" (
    builtins.toJSON {
      inherit component revision;
      systems = builtins.attrNames jobs;
    }
  );
  expressions = pkgs.writeText "default.nix" ''
    { system ? builtins.currentSystem }:
    (builtins.getFlake "github:hellas-ai/hellas/${revision}").releaseJobs.${component}.''${system}.artifacts
  '';
  source = pkgs.runCommand "hellas-${component}-channel-source" { } ''
    mkdir -p "$out"
    cp ${manifest} "$out/release.json"
    cp ${expressions} "$out/default.nix"
  '';
in
pkgs.releaseTools.channel {
  name = "hellas-${component}";
  src = source;
  isNixOS = false;
  constituents = map (jobs: jobs.release) (builtins.attrValues jobs);
}
