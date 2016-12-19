{ nixpkgs ? import <nixpkgs> {}, compiler ? "default" }:

let
  inherit (nixpkgs) pkgs;

  haskellPackages = if compiler == "default"
                       then pkgs.haskellPackages
                       else pkgs.haskell.packages.${compiler};

  haskellPackages_ = haskellPackages.override {
    overrides = self: super: {
      cryptonite = self.callPackage ./cryptonite-0.21.nix {};
    };
  };

  drv = haskellPackages_.callPackage ./default.nix {};

in 
  if pkgs.lib.inNixShell then drv.env else drv
