{
  description = "Hellas Node";

  # The binary cache is opt-in for downstream users: nix prompts on first use
  # (or accepts it with `--accept-flake-config`).
  nixConfig = {
    extra-substituters = [ "https://cache.hellas.ai" ];
    extra-trusted-public-keys = [ "cache.hellas.ai-1:PYolh95U/Ms5fKE+NQTcNZUHyEv4QikaNocg9I9iy0g=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    # Public, pinned HIP 7.15+ ROCm package set.
    nix-strix-halo = {
      url = "github:hellas-ai/nix-strix-halo/e24b2efcfaee1cefd326ff65ff7a955a908fd5ee";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      nix-strix-halo,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      hydraSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      forHydraSystems = nixpkgs.lib.genAttrs hydraSystems;
      perSystem = forAllSystems (
        system:
        import ./nix {
          inherit
            self
            system
            nixpkgs
            rust-overlay
            ;
        }
      );
    in
    {
      packages = forAllSystems (system: perSystem.${system}.packages);
      apps = forAllSystems (system: perSystem.${system}.apps);
      devShells = forAllSystems (system: perSystem.${system}.devShells);
      checks = forAllSystems (system: perSystem.${system}.checks);
      nixosTests = forAllSystems (system: perSystem.${system}.nixosTests);
      ci = forAllSystems (system: perSystem.${system}.ci);
      hydraJobs = forHydraSystems (system: perSystem.${system}.hydraJobs);
      formatter = forAllSystems (system: perSystem.${system}.formatter);

      overlays.default = final: _prev: {
        hellas = self.packages.${final.system};
        hellasLib = import ./nix/lib {
          pkgs = final;
          inherit nix-strix-halo;
        };
      };

      nixosModules = {
        hellas = import ./nix/modules/nixos.nix { inherit self; };
        validators = import ./nix/modules/validators.nix { inherit self; };
        default = self.nixosModules.hellas;
      };

      homeManagerModules.hellas = import ./nix/modules/home-manager.nix { inherit self; };
      homeManagerModules.default = self.homeManagerModules.hellas;
    };
}
