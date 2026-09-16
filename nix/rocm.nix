{ pkgs, nix-strix-halo }:
# The upstream flake's public package set avoids importing private recipes.
nix-strix-halo.legacyPackages.${pkgs.stdenv.hostPlatform.system}.gfx1151.therockRocmPackages
