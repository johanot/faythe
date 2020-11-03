let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs {};
  crate2nix = pkgs.callPackage (import sources.crate2nix) {};
in
pkgs.mkShell {
  buildInputs = with pkgs; [
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
