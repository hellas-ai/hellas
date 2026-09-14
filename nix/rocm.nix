{ pkgs, nix-strix-halo }:
# The source scope is architecture-independent. No TheRock binary SDK or
# HSA_OVERRIDE_GFX_VERSION is used; hipcc compiles for the actual provider GPU.
# `legacyPackages` is the upstream flake's public escape hatch for its pinned
# ROCm target package set. Use it directly instead of importing its private
# package recipes and reconstructing part of its flake lock here.
nix-strix-halo.legacyPackages.${pkgs.stdenv.hostPlatform.system}.gfx1151.therockRocmPackages
