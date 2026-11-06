{
  description = "Hellas Node";

  # The binary cache is opt-in for downstream users: nix prompts on first use
  # (or accepts it with `--accept-flake-config`).
  nixConfig = {
    extra-substituters = [ "https://cache.hellas.ai" ];
    extra-trusted-public-keys = [ "cache.hellas.ai-1:PYolh95U/Ms5fKE+NQTcNZUHyEv4QikaNocg9I9iy0g=" ];
  };

  inputs = {
    # Downstream repositories share these pins instead of keeping their own:
    #   inputs.nixpkgs.follows = "hellas/nixpkgs";
    #   inputs.rust-overlay.follows = "hellas/rust-overlay";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
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
      # crane is used through self.inputs in nix/package.nix.
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      releaseSystems = systems;
      forAllSystems = nixpkgs.lib.genAttrs systems;
      forReleaseSystems = nixpkgs.lib.genAttrs releaseSystems;
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
      # Flake plumbing shared with downstream repositories.
      lib = { inherit systems forAllSystems; };

      packages = forAllSystems (system: perSystem.${system}.packages);
      apps = forAllSystems (system: perSystem.${system}.apps);
      devShells = forAllSystems (system: perSystem.${system}.devShells);
      checks = forAllSystems (system: perSystem.${system}.checks);
      nixosTests = forAllSystems (system: perSystem.${system}.nixosTests);
      ci = forAllSystems (system: perSystem.${system}.ci);
      # The `hellas` Hydra jobset builds master and admitted PRs. It builds the
      # compiled dependencies only, so GitHub-hosted checks substitute them
      # from cache.hellas.ai; the checks themselves run on GitHub.
      hydraJobs.x86_64-linux = { inherit (perSystem.x86_64-linux.checks) cargo-deps; };
      # Selected explicitly by the component's Hydra jobset, never by PR CI.
      releaseJobs =
        builtins.mapAttrs
          (
            component: jobs:
            jobs
            // {
              channel = import ./nix/release-channel.nix {
                pkgs = nixpkgs.legacyPackages.x86_64-linux;
                inherit self component jobs;
              };
            }
          )
          {
            cli = forReleaseSystems (system: perSystem.${system}.releaseJobs.cli);
            gpu.x86_64-linux = perSystem.x86_64-linux.releaseJobs.gpu;
            consensus.x86_64-linux = perSystem.x86_64-linux.releaseJobs.consensus;
          };
      # CI-only Windows cross build and on-Windows smoke test; see nix/default.nix.
      windowsJobs.x86_64-linux = perSystem.x86_64-linux.windowsJobs;
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

      darwinModules.hellas = import ./nix/modules/darwin.nix { inherit self; };
      darwinModules.default = self.darwinModules.hellas;

      homeManagerModules.hellas = import ./nix/modules/home-manager.nix { inherit self; };
      homeManagerModules.default = self.homeManagerModules.hellas;
    };
}
