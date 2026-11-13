{
  self,
  pkgs,
  lib,
  package,
  portablePackage,
  validatorPackage,
}:
(import ./basic.nix {
  inherit pkgs package portablePackage;
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
  inherit pkgs lib;
  validatorPackage = validatorPackage.override { otel = true; };
})
