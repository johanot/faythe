let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs {};
  crate2nix = pkgs.callPackage (import sources.crate2nix) {};
  bump-o-matic = pkgs.callPackage (import "${sources.detached-ci}/rust-ci/rust-bump-o-matic.nix") {};
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    bump-o-matic
    cargo
    crate2nix
    niv
    openssl.dev
    pkgconfig
    rustc
    zlib.dev
    dnsutils # runtime
    kubectl # runtime
  ];
}
