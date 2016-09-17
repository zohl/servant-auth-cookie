{ mkDerivation, base, base64-bytestring, blaze-builder, blaze-html
, blaze-markup, bytestring, cereal, cookie, criterion, cryptonite
, data-default, deepseq, exceptions, hspec, http-media, http-types
, memory, mtl, QuickCheck, servant, servant-blaze, servant-server
, stdenv, text, time, transformers, wai, warp
}:
mkDerivation {
  pname = "servant-auth-cookie";
  version = "0.3.2";
  src = ./.;
  isLibrary = true;
  isExecutable = true;
  libraryHaskellDepends = [
    base base64-bytestring blaze-builder bytestring cereal cookie 
    cryptonite data-default exceptions http-types memory mtl servant
    servant-server time transformers wai
  ];
  executableHaskellDepends = [
    base blaze-html blaze-markup bytestring cereal cryptonite
    data-default http-media mtl servant servant-blaze servant-server
    text wai warp
  ];
  testHaskellDepends = [
    base bytestring cereal criterion cryptonite data-default deepseq hspec
    QuickCheck servant-server time
  ];
  description = "Authentication via encrypted cookies";
  license = stdenv.lib.licenses.bsd3;
}
