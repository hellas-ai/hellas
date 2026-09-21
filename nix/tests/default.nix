{
  self,
  pkgs,
  lib,
  package,
  networkPackage,
  validatorPackage,
}:
(import ./basic.nix {
  inherit pkgs package networkPackage;
})
// (import ./module-eval.nix {
  inherit
    self
    pkgs
    lib
    package
    ;
})
// (import ./e2e.nix {
  inherit
    self
    pkgs
    lib
    ;
  package = package.override { otel = true; };
  validatorPackage = validatorPackage.override { otel = true; };
})
