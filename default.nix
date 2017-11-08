{ mkDerivation, base, base-compat, base64-bytestring, blaze-builder
, blaze-html, blaze-markup, bytestring, cereal, cookie, criterion
, cryptonite, data-default, deepseq, directory, exceptions
, filepath, hspec, hspec-wai, http-api-data, http-media, http-types
, memory, mtl, QuickCheck, servant, servant-blaze, servant-server
, stdenv, tagged, text, time, transformers, wai, wai-extra, warp
}:
mkDerivation {
  pname = "servant-auth-cookie";
  version = "0.5.0.7";
  src = ./.;
  configureFlags = [ "-fbuild-examples" "-fservant91" ];
  isLibrary = true;
  isExecutable = true;
  libraryHaskellDepends = [
    base base64-bytestring blaze-builder bytestring cereal cookie
    cryptonite data-default exceptions http-api-data http-types memory
    mtl servant servant-server tagged time transformers wai
  ];
  executableHaskellDepends = [
    base base-compat base64-bytestring blaze-html blaze-markup
    bytestring cereal cryptonite data-default directory exceptions
    filepath http-api-data http-media http-types mtl servant
    servant-blaze servant-server text time transformers wai warp
  ];
  testHaskellDepends = [
    base base-compat base64-bytestring blaze-html blaze-markup
    bytestring cereal cryptonite data-default deepseq directory
    exceptions filepath hspec hspec-wai http-api-data http-media
    http-types mtl QuickCheck servant servant-blaze servant-server text
    time transformers wai wai-extra
  ];
  benchmarkHaskellDepends = [
    base bytestring criterion cryptonite servant-server
  ];
  description = "Authentication via encrypted cookies";
  license = stdenv.lib.licenses.bsd3;
}
