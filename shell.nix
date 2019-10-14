let
  moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  _pkgs = import <nixpkgs> {};
  pkgs = import (_pkgs.fetchFromGitHub {
    owner = "NixOS";
    repo = "nixpkgs-channels";
    rev = "222004e52e82ae7b827b20184d25c1ce88b85da6";
    sha256 = "00wv3bpyqp8cc2rb8mnfdy5xv28bn43qal9316jfmczdmnpvqpyg";
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
