{-# LANGUAGE CPP                   #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}

module Main (main) where
import AuthAPI (app, authSettings)
import Prelude ()
import Prelude.Compat
import Crypto.Random (drgNew)
import Network.Wai.Handler.Warp (run)
import Servant.Server.Experimental.Auth.Cookie

main :: IO ()
main = do
  rs <- mkRandomSource drgNew 1000
  -- let sks = PersistentServerKey "123456789abcdef"
  sks <- mkExampleKeySet 4 16
  -- sks <- mkRenewableKeySet 8 16 4 []
  run 8080 (app authSettings rs sks)

