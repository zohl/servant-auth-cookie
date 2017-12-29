{ nixpkgs ? import <nixpkgs> {}, compiler ? "default" }:

let
  inherit (nixpkgs) pkgs;
  dontCheck = pkgs.haskell.lib.dontCheck;

  haskellPackages = if compiler == "default"
                       then pkgs.haskellPackages
                       else pkgs.haskell.packages.${compiler};

  haskellPackages_ = haskellPackages.override {
    overrides = self: super: {
cereal-time = dontCheck (self.callPackage /home/user/src/haskell/_deps/cereal-time-0.1.0.0.nix {});
    };
  };

  drv = haskellPackages_.callPackage ./default.nix {};

in
  if pkgs.lib.inNixShell then drv.env else drv
