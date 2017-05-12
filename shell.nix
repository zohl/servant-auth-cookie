{ nixpkgs ? import <nixpkgs> {}, compiler ? "default" }:

let
  inherit (nixpkgs) pkgs;
  dontCheck = pkgs.haskell.lib.dontCheck;

  haskellPackages = if compiler == "default"
                       then pkgs.haskellPackages
                       else pkgs.haskell.packages.${compiler};

  haskellPackages_ = haskellPackages.override {
    overrides = self: super: {
      # cryptonite = dontCheck (self.callPackage ./deps/cryptonite-0.23.nix {});
      # foundation = dontCheck (self.callPackage ./deps/foundation-0.0.8.nix {});
      # memory = dontCheck (self.callPackage ./deps/memory-0.14.5.nix {});
    };
  };

  drv = haskellPackages_.callPackage ./default.nix {};

in
  if pkgs.lib.inNixShell then drv.env else drv
