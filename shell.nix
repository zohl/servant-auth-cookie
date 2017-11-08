{ nixpkgs ? import <nixpkgs> {}, compiler ? "default" }:

let
  inherit (nixpkgs) pkgs;
  dontCheck = pkgs.haskell.lib.dontCheck;

  haskellPackages = if compiler == "default"
                       then pkgs.haskellPackages
                       else pkgs.haskell.packages.${compiler};

  haskellPackages_ = haskellPackages.override {
    overrides = self: super: {
    };
  };

  drv = haskellPackages_.callPackage ./default.nix {};

in
  if pkgs.lib.inNixShell then drv.env else drv
