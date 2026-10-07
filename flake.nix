{
  description = "SecretSpec development environment";

  # Reuse the revisions selected by the existing devenv environment.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/2f3aa44ed8975f834c76d5ca91b11c42c3158097";
    devenv = {
      url = "github:cachix/devenv/00832edc267fb93e71f1b4929c89b3ae4a637e0c";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.git-hooks.follows = "git-hooks";
      inputs.rust-overlay.follows = "rust-overlay";
    };
    git-hooks = {
      url = "github:cachix/git-hooks.nix/809414f0cdadf82cf11b06c2b29ba9b3168b3297";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay/89e26eeaafa88a2ede4778734acc794ff0299beb";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  nixConfig = {
    extra-trusted-public-keys = "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw=";
    extra-substituters = "https://devenv.cachix.org";
  };

  outputs = { nixpkgs, devenv, ... }@inputs:
    let
      systems = [ "x86_64-linux" ];
    in {
      devShells = nixpkgs.lib.genAttrs systems (system: {
        default = devenv.lib.mkShell {
          inherit inputs;
          pkgs = nixpkgs.legacyPackages.${system};
          modules = [ ./devenv.nix ];
        };
      });
    };
}
