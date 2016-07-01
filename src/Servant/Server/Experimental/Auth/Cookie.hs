-- {-# LANGUAGE DataKinds                  #-}
-- {-# LANGUAGE FlexibleContexts           #-}
-- {-# LANGUAGE GADTs                      #-}
-- {-# LANGUAGE OverloadedStrings          #-}
-- {-# LANGUAGE TypeFamilies               #-}
-- {-# LANGUAGE ScopedTypeVariables        #-}
-- {-# LANGUAGE PartialTypeSignatures      #-}
-- {-# LANGUAGE Rank2Types                 #-}

module Servant.Server.Experimental.Auth.Cookie (
    AuthCookieData
  , Cookie(..)

  , Settings(..)
  , defaultSettings

  , mkRandomSource
  , mkServerKey

  , encryptCookie
  , decryptCookie

  , encryptSession
  , decryptSession

  , addSession
  , getSession

  , defaultAuthHandler
  ) where

import Servant.Server.Experimental.Auth.Cookie.Internal


