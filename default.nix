{ mkDerivation, base, base64-bytestring, blaze-builder, bytestring
, cereal, cookie, cryptonite, data-default, deepseq, exceptions
, hspec, http-api-data, http-types, memory, mtl, QuickCheck
, servant, servant-server, stdenv, tagged, time, transformers, wai
, hspec-wai, servant-blaze, criterion
}:
mkDerivation {
  pname = "servant-auth-cookie";
  version = "0.5.0.6";
  src = ./.;
  libraryHaskellDepends = [
    base base64-bytestring blaze-builder bytestring cereal cookie
    cryptonite data-default exceptions http-api-data http-types memory
    mtl servant servant-server tagged time transformers wai criterion
  ];
  testHaskellDepends = [
    base bytestring cereal cryptonite data-default deepseq hspec
    QuickCheck servant-server time hspec-wai servant-blaze
  ];
  description = "Authentication via encrypted cookies";
  license = stdenv.lib.licenses.bsd3;
}
