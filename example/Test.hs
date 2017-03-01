{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}

import Prelude ()
import Prelude.Compat
import AuthAPI (app, authSettings, LoginForm(..), homePage, loginPage)
import Control.Concurrent (threadDelay)
import Control.Exception.Base (bracket)
import Control.Monad (guard, when)
import Network.Wai (Application)
import Test.Hspec (Spec, hspec, describe, it)
import Test.Hspec.Wai (matchBody, shouldRespondWith, liftIO, with, request, get, post)
import Text.Blaze.Renderer.Utf8 (renderMarkup)
import Servant (Proxy(..))
import Servant.Server (serve)
import System.IO (openTempFile, hClose)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Char8 as BSLC8
import Crypto.Random (drgNew)
import Servant (FormUrlEncoded(..), contentType)
import Servant.Server.Experimental.Auth.Cookie
import Network.HTTP.Types (methodGet, methodPost, hContentType, hCookie)
import Network.HTTP.Media.RenderHeader (renderHeader)
import Network.Wai.Test (SResponse(..))

#if MIN_VERSION_servant (0,9,0)
import Web.FormUrlEncoded (toForm)
#else
import Servant (ToFormUrlEncoded, toFormUrlEncoded, mimeRender)
#endif


#if MIN_VERSION_servant (0,9,0)
-- TODO
#else
encode :: ToFormUrlEncoded a => a -> BSL.ByteString
encode = mimeRender (Proxy :: Proxy FormUrlEncoded)
#endif


main :: IO ()
main = hspec spec

spec :: Spec
spec = with mkApp $ do

  let formContentType = (
          hContentType
        , renderHeader $ contentType (Proxy :: Proxy FormUrlEncoded))

  describe "home page" $ do
    it "responds successfully" $ do
      get "/" `shouldRespondWith` 200 {
        matchBody = Just . renderMarkup $ homePage
        }

  describe "login page" $ do
    it "responds successfully" $ do
      get "/login" `shouldRespondWith` 200 {
        matchBody = Just . renderMarkup $ loginPage True
        }

    it "shows message on incorrect login" $ do
      let loginForm = encode $ LoginForm {
            lfUsername = "noname"
          , lfPassword = "noname"
          }
      let r = request methodPost "/login" [formContentType] loginForm
      r `shouldRespondWith` 200 {
        matchBody = Just . renderMarkup $ loginPage False
        }


  describe "private page" $ do
    it "rejects requests without cookies" $ do
      let r = get "/private"
      r `shouldRespondWith` 403 { matchBody = Just "User doesn't exist" }


    it "accepts requests with proper cookies" $ do
      let loginForm = encode $ LoginForm {
            lfUsername = "mr_foo"
          , lfPassword = "password1"
          }

      (SResponse {..}) <- request methodPost "/login" [formContentType] loginForm
      let cookieValue = maybe "" id (lookup "set-cookie" simpleHeaders)

      let r = request methodGet "/private" [(hCookie, cookieValue)] ""
      r `shouldRespondWith` 200

mkApp :: IO Application
mkApp = do
  rs <- mkRandomSource drgNew 1000
  sk <- mkServerKey 16 Nothing
  return (app authSettings rs sk)

