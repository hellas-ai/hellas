{
  self,
  pkgs,
  lib,
  package,
  validatorPackage,
}:
(import ./basic.nix {
  inherit pkgs package;
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
