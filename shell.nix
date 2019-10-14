let
  moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  _pkgs = import <nixpkgs> {};
  pkgs = import (_pkgs.fetchFromGitHub {
    owner = "NixOS";
    repo = "nixpkgs-channels";
    rev = "e19054ab3cd5b7cc9a01d0efc71c8fe310541065";
    sha256 = "0b92yhkj3pq58svyrx7jp0njhaykwr29079izqn6qs638v8zvhl2";
  }) {
    overlays = [moz_overlay];
  };
 
in
  pkgs.mkShell {
    buildInputs = with pkgs; [
      gcc
      pkgconfig
      openssl.dev
      zlib.dev
      latest.rustChannels.stable.rust
      dnsutils  # runtime
      kubectl   # runtime
    ];
  }
