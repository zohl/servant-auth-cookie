{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where
import AuthAPI (app, authSettings)
import Prelude ()
import Prelude.Compat
import Crypto.Random (drgNew)
import Network.Wai.Handler.Warp (run)
import Servant.Server.Experimental.Auth.Cookie

#if MIN_VERSION_servant (0,9,1) && MIN_VERSION_directory (1,2,5)
import FileKeySet (mkFileKeySet, FileKSParams(..), mkFileKey)
#endif

-- To use mutable server keys we need servant-9.1 and
-- directory-1.2.5 (or higher). Otherwise the only (sane) choice is a
-- persistent key.

main :: IO ()
main = do
  rs <- mkRandomSource drgNew 1000

#if MIN_VERSION_servant (0,9,1) && MIN_VERSION_directory (1,2,5)
  let fksp = FileKSParams
        { fkspKeySize = 16
        , fkspMaxKeys = 3
        , fkspPath = "./test-key-set"
        }

  k <- mkFileKeySet fksp
  let generateKey = mkFileKey fksp
#else
  let k = mkPersistentServerKey "0123456789abcdef"
  let generateKey = return ()
#endif

  run 8080 (app authSettings generateKey rs k)
