{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
    crane = {
      url = "github:ipetkov/crane";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };
  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            (pkgs.lib.hasSuffix "\.css" path) ||
            (pkgs.lib.hasSuffix "\.js" path) ||
            (pkgs.lib.hasSuffix "\.svg" path) ||
            (craneLib.filterCargoSources path type)
          ;
        };
        commonArgs = {
          inherit src;
          buildInputs = [ pkgs.git ];
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        bin = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });

        docker = pkgs.dockerTools.buildLayeredImage {
          name = "quizzy";
          tag = "latest";
          created = "now";
          contents = with pkgs; [ cacert ];
          config.Cmd = [ "${bin}/bin/quizzy" ];
          config.Expose = "1414";
        };
      in
      {
        packages = {
          default = bin;
          docker = docker;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.bacon
            pkgs.httpie
            pkgs.cargo-dist
            pkgs.cargo-watch
            pkgs.rust-analyzer
            rustToolchain
          ];
        };

        formatter = pkgs.nixpkgs-fmt;
      }
    );
}
