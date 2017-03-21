{-# LANGUAGE CPP                   #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}

module Main (main) where
import AuthAPI (app, authSettings, mkFileKeySet, FileKSParams(..), mkFileKey)
import Prelude ()
import Prelude.Compat
import Data.Default (def)
import Crypto.Random (drgNew)
import Network.Wai.Handler.Warp (run)
import Servant.Server.Experimental.Auth.Cookie


main :: IO ()
main = do
  rs <- mkRandomSource drgNew 1000
  let fksp = FileKSParams
        { fkspKeySize = 16
        , fkspMaxKeys = 3
        , fkspPath = "./test-key-set"
        }

  k <- mkFileKeySet fksp

  run 8080 (app authSettings (mkFileKey fksp) rs k)

