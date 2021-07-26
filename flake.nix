{
  description = "faythe";

  inputs = {
    facts.url = "git+https://gitlab.dbc.dk/it/facts.git";
    nixpkgs.follows = "facts/nixpkgs-default";
    ci.url = "git+https://gitlab.dbc.dk/platform/bump-o-matic.git";
    ci.inputs.nixpkgs.follows = "facts/nixpkgs-default";
  };

  outputs = { self, nixpkgs, facts, ci }:
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
