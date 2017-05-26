{ nixpkgs ? import <nixpkgs> {}, compiler ? "default" }:

let
  inherit (nixpkgs) pkgs;
  dontCheck = pkgs.haskell.lib.dontCheck;

  haskellPackages = if compiler == "default"
                       then pkgs.haskellPackages
                       else pkgs.haskell.packages.${compiler};

  haskellPackages_ = haskellPackages.override {
    overrides = self: super: {
      criterion = dontCheck (self.callPackage ../_deps/criterion-1.2.nix {});
      microstache = dontCheck (self.callPackage ../_deps/microstache-1.nix {});
      statistics = dontCheck (self.callPackage ../_deps/statistics-0.14.0.2.nix {});
      base-orphans = dontCheck (self.callPackage ../_deps/base-orphans-0.6.nix {});
    };
  };

  drv = haskellPackages_.callPackage ./default.nix {};

in
  if pkgs.lib.inNixShell then drv.env else drv
