{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}

import Prelude ()
import Prelude.Compat
import Data.Maybe (fromMaybe)
import Data.Int (Int64)
import Data.Time.Clock (UTCTime(..))
import Control.Monad.IO.Class (liftIO)
import AuthAPI (app, authSettings, LoginForm(..), homePage, loginPage, Account(..))
import Test.Hspec (Spec, hspec, describe, it)
import Test.Hspec.Wai (WaiSession, WaiExpectation, shouldRespondWith, with, request, get)
import Text.Blaze.Renderer.Utf8 (renderMarkup)
import Servant (Proxy(..))
import Crypto.Random (drgNew)
import Servant (FormUrlEncoded, contentType)
import Servant.Server.Experimental.Auth.Cookie
import Network.HTTP.Types (methodGet, methodPost, hContentType, hCookie)
import Network.HTTP.Media.RenderHeader (renderHeader)
import Network.Wai.Test (SResponse(..))
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Char8 as BSC8

#if MIN_VERSION_hspec_wai (0,7,0)
import Test.Hspec.Wai.Matcher (bodyEquals, ResponseMatcher(..), MatchBody(..))
#else
import Test.Hspec.Wai (matchBody)
#endif

#if MIN_VERSION_servant (0,9,0)
import Web.FormUrlEncoded (ToForm, toForm, urlEncodeForm)
#else
import Servant (ToFormUrlEncoded, mimeRender)
#endif


data SpecState = SpecState {
    ssRandomSource :: RandomSource
  , ssServerKey    :: ServerKey
  , ssAuthSettings :: AuthCookieSettings
  }

main :: IO ()
main = withState (hspec . spec) where
  withState f = do
    let ssAuthSettings = authSettings
    ssRandomSource <- mkRandomSource drgNew 1000
    ssServerKey <- mkServerKey 16 Nothing
    f $ SpecState {..}


spec :: SpecState -> Spec
spec SpecState {..} = with (return $ app ssAuthSettings ssRandomSource ssServerKey) $ do

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
    let loginForm = encode $ LoginForm {
          lfUsername = "mr_foo"
        , lfPassword = "password1"
        }
    let loginRequest = request methodPost "/login" [formContentType] loginForm

    it "rejects requests without cookies" $ do
      let r = get "/private"
      r `shouldRespondWith` 403 { matchBody = matchBody' "No cookies" }

    it "accepts requests with proper cookies" $ do
      (SResponse {..}) <- loginRequest
      let cookieValue = fromMaybe
            (error "cookies aren't available")
            (lookup "set-cookie" simpleHeaders)

      let r = request methodGet "/private" [(hCookie, cookieValue)] ""
      r `shouldRespondWith` 200

    it "accepts requests with proper cookies (sanity check)" $ do
      (SResponse {..}) <- loginRequest

      cookieValue <- liftIO $ do
        session <- maybe
          (error "cookies aren't available")
          (decryptSession ssAuthSettings ssServerKey)
          (parseSessionResponse ssAuthSettings simpleHeaders) :: IO Account

        renderSession ssAuthSettings ssRandomSource ssServerKey session

      let r = request methodGet "/private" [(hCookie, cookieValue)] ""
      r `shouldRespondWith` 200


    it "rejects requests with incorrect MAC" $ do
      (SResponse {..}) <- loginRequest

      cookieValue <- liftIO $ do
        session <- maybe
          (error "cookies aren't available")
          (decryptSession ssAuthSettings ssServerKey)
          (parseSessionResponse ssAuthSettings simpleHeaders) :: IO Account

        sk <- mkServerKey 16 Nothing
        renderSession ssAuthSettings ssRandomSource sk session

      let r = request methodGet "/private" [(hCookie, cookieValue)] ""

      r `shouldRespondWithException` (IncorrectMAC "")


    it "rejects requests with malformed expiration time" $ do
      (SResponse {..}) <- loginRequest

      cookieValue <- liftIO $ do
        session <- maybe
          (error "cookies aren't available")
          (decryptSession ssAuthSettings ssServerKey)
          (parseSessionResponse ssAuthSettings simpleHeaders) :: IO Account

        renderSession
          ssAuthSettings { acsExpirationFormat = "%0Y%m%d" }
          ssRandomSource
          ssServerKey
          session

      let r = request methodGet "/private" [(hCookie, cookieValue)] ""
      r `shouldRespondWithException` (CannotParseExpirationTime "")


    it "rejects requests with expired cookies" $ do
      (SResponse {..}) <- loginRequest

      cookieValue <- liftIO $ do
        session <- maybe
          (error "cookies aren't available")
          (decryptSession ssAuthSettings ssServerKey)
          (parseSessionResponse ssAuthSettings simpleHeaders) :: IO Account

        renderSession
          ssAuthSettings { acsMaxAge = 0 }
          ssRandomSource
          ssServerKey
          session

      let r = request methodGet "/private" [(hCookie, cookieValue)] ""
      let dummyTime = UTCTime (toEnum 0) 0

      r `shouldRespondWithException` (CookieExpired dummyTime dummyTime)


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

shrinkBody :: Int64 -> SResponse -> SResponse
shrinkBody len r = r { simpleBody = BSL.take len $ simpleBody r }

shouldRespondWithException :: WaiSession SResponse -> AuthCookieException -> WaiExpectation
shouldRespondWithException req ex = do
  let exception = BSC8.pack . head . words . show $ ex
  (shrinkBody (BSC8.length exception) <$> req) `shouldRespondWith` 403 {
    matchBody = matchBody' exception
    }

