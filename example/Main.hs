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
  -- NOTE:
  -- Every time the application is executed, a new server key is
  -- created. This means, once you restart the app, already existing
  -- cookies will be invalidated.
  sk <- mkServerKey 16 Nothing
  run 8080 (app authSettings rs sk)

