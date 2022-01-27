{
  description = "faythe";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-21.11";
    ci.url = "git+https://gitlab.dbc.dk/platform/bump-o-matic.git";
    ci.inputs.nixpkgs.follows = "nixpkgs";
    ci.inputs.utils.follows = "utils";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, ci, utils }:
  let
    pname = "faythe";
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ ci.overlay ];
    };
  in {
    packages.${system}.${pname} = (import ./Cargo.nix {
      inherit pkgs;
    }).rootCrate.build;

    defaultPackage.${system} = self.packages.${system}.${pname};

    devShell.${system} = with pkgs; mkShell {
      buildInputs = [
        cargo
        crate2nix
        openssl.dev
        pkgconfig
        rustc
        zlib.dev
        dnsutils # runtime
        kubectl # runtime
        bump-o-matic
        bump-rust
      ];
    };
  };
}
