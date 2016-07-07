-- {-# LANGUAGE DataKinds                  #-}
-- {-# LANGUAGE FlexibleContexts           #-}
-- {-# LANGUAGE GADTs                      #-}
-- {-# LANGUAGE OverloadedStrings          #-}
-- {-# LANGUAGE TypeFamilies               #-}
-- {-# LANGUAGE ScopedTypeVariables        #-}
-- {-# LANGUAGE PartialTypeSignatures      #-}
-- {-# LANGUAGE Rank2Types                 #-}


{-|
  Module:      Servant.Server.Experimental.Auth.Cookie
  Copyright:   (c) 2016 Al Zohali
  License:     GPL3
  Maintainer:  Al Zohali <zohl@fmap.me>
  Stability:   experimental


  = Description

  Authentication via encrypted client-side cookies, inspired by
  client-session library by Michael Snoyman and based on ideas of the
  paper "A Secure Cookie Protocol" by Alex Liu et al.
-}

module Servant.Server.Experimental.Auth.Cookie (
    RandomSource
  , ServerKey

  , CipherAlgorithm
  , AuthCookieData
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


