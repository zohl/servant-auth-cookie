{ nixpkgs ? import <nixpkgs> {}, compiler ? "default" }:

let
  inherit (nixpkgs) pkgs;
  dontCheck = pkgs.haskell.lib.dontCheck;

  haskellPackages = if compiler == "default"
                       then pkgs.haskellPackages
                       else pkgs.haskell.packages.${compiler};

  haskellPackages_ = haskellPackages.override {
    overrides = self: super: {
      servant = self.servant_0_10;
      servant-server = self.servant-server_0_10;
      natural-transformation = dontCheck self.natural-transformation_0_4;
      hspec-wai = dontCheck self.hspec-wai_0_8_0;
      hspec-expectations = dontCheck self.hspec-expectations_0_8_2;
      hspec-meta = dontCheck self.hspec-meta_2_3_2;
      hspec-core = dontCheck self.hspec-core_2_4_1;
      hspec = dontCheck self.hspec_2_4_1;
      hspec-discover = dontCheck self.hspec-discover_2_4_1;
    };
  };

  drv = haskellPackages_.callPackage ./default.nix {};

in
  if pkgs.lib.inNixShell then drv.env else drv
