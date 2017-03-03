{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}

import Prelude ()
import Prelude.Compat
import AuthAPI (app, authSettings, LoginForm(..), homePage, loginPage)
import Network.Wai (Application)
import Test.Hspec (Spec, hspec, describe, it)
import Test.Hspec.Wai (shouldRespondWith, with, request, get)
import Text.Blaze.Renderer.Utf8 (renderMarkup)
import Servant (Proxy(..))
import qualified Data.ByteString.Lazy as BSL
import Crypto.Random (drgNew)
import Servant (FormUrlEncoded, contentType)
import Servant.Server.Experimental.Auth.Cookie
import Network.HTTP.Types (methodGet, methodPost, hContentType, hCookie)
import Network.HTTP.Media.RenderHeader (renderHeader)
import Network.Wai.Test (SResponse(..))

#if MIN_VERSION_hspec_wai (0,7,0)
import Test.Hspec.Wai.Matcher (bodyEquals, ResponseMatcher(..), MatchBody)
#else
import Test.Hspec.Wai (matchBody)
#endif

#if MIN_VERSION_servant (0,9,0)
import Web.FormUrlEncoded (ToForm, toForm, urlEncodeForm)
#else
import Servant (ToFormUrlEncoded, mimeRender)
#endif


#if MIN_VERSION_hspec_wai (0,7,0)
matchBody' :: BSL.ByteString -> MatchBody
matchBody' = bodyEquals
#else
matchBody' :: BSL.ByteString -> Maybe BSL.ByteString
matchBody' = Just
#endif

#if MIN_VERSION_servant (0,9,0)
encode :: ToForm a => a -> BSL.ByteString
encode = urlEncodeForm . toForm
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
        matchBody = matchBody' $ renderMarkup homePage
        }

  describe "login page" $ do
    it "responds successfully" $ do
      get "/login" `shouldRespondWith` 200 {
        matchBody = matchBody' $ renderMarkup (loginPage True)
        }

    it "shows message on incorrect login" $ do
      let loginForm = encode $ LoginForm {
            lfUsername = "noname"
          , lfPassword = "noname"
          }
      let r = request methodPost "/login" [formContentType] loginForm
      r `shouldRespondWith` 200 {
        matchBody = matchBody' $ renderMarkup (loginPage False)
        }

  describe "private page" $ do
    it "rejects requests without cookies" $ do
      let r = get "/private"
      r `shouldRespondWith` 403 { matchBody = matchBody' "User doesn't exist" }

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

