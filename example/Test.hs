{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE GADTs #-}

import Prelude ()
import Prelude.Compat
import Data.Maybe (fromMaybe)
import Data.Int (Int64)
import Data.Time.Clock (UTCTime(..))
import Control.Monad.IO.Class (liftIO)
import AuthAPI (app, authSettings, LoginForm(..), homePage, loginPage, Account(..))
import Test.Hspec (Spec, hspec, describe, context, it)
import Test.Hspec.Wai (WaiSession, WaiExpectation, shouldRespondWith, with, request, get)
import Text.Blaze.Renderer.Utf8 (renderMarkup)
import Text.Blaze (Markup)
import Servant (Proxy(..))
import Crypto.Random (drgNew)
import Servant (FormUrlEncoded, contentType)
import Servant.Server.Experimental.Auth.Cookie
import Network.HTTP.Types (Header, methodGet, methodPost, hContentType, hCookie)
import Network.HTTP.Media.RenderHeader (renderHeader)
import Network.Wai.Test (SResponse(..))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Char8 as BSLC8

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


data SpecState where
  SpecState :: (ServerKeySet k) =>
    { ssRandomSource :: RandomSource
    , ssAuthSettings :: AuthCookieSettings
    , ssServerKeySet :: k
    } -> SpecState

main :: IO ()
main = do
  rs <- mkRandomSource drgNew 1000

  hspec . basicSpec . SpecState rs authSettings $
    mkPersistentServerKey "0123456789abcdef"


basicSpec :: SpecState -> Spec
basicSpec ss@(SpecState {..}) = describe "basic functionality" $ with
  (return $ app ssAuthSettings ssRandomSource ssServerKeySet) $ do

  context "home page" $ do
    it "responds successfully" $ do
      get "/" `shouldRespondWithMarkup` homePage

  context "login page" $ do
    it "responds successfully" $ do
      get "/login" `shouldRespondWithMarkup` (loginPage True)

    it "shows message on incorrect login" $ do
      login "noname" "noname" `shouldRespondWithMarkup` (loginPage False)

  context "private page" $ do
    let loginRequest = login "mr_foo" "password1"

    it "rejects requests without cookies" $ do
      get "/private" `shouldRespondWith` 403 { matchBody = matchBody' "No cookies" }

    it "accepts requests with proper cookies" $ do
      (SResponse {..}) <- loginRequest
      let cookieValue = fromMaybe
            (error "cookies aren't available")
            (lookup "set-cookie" simpleHeaders)
      getPrivate cookieValue `shouldRespondWith` 200

    it "accepts requests with proper cookies (sanity check)" $ do
      cookieValue <- loginRequest
        >>= liftIO . forgeCookies ss authSettings ssServerKeySet
      getPrivate cookieValue `shouldRespondWith` 200

    it "rejects requests with incorrect MAC" $ do
      let newServerKeySet = mkPersistentServerKey "0000000000000000"
      cookieValue <- loginRequest
        >>= liftIO . forgeCookies ss authSettings newServerKeySet
      getPrivate cookieValue `shouldRespondWithException` (IncorrectMAC "")

    it "rejects requests with malformed expiration time" $ do
      let newAuthSettings = authSettings { acsExpirationFormat = "%0Y%m%d" }
      cookieValue <- loginRequest
        >>= liftIO . forgeCookies ss newAuthSettings ssServerKeySet
      getPrivate cookieValue `shouldRespondWithException` (CannotParseExpirationTime "")

    it "rejects requests with expired cookies" $ do
      let newAuthSettings = authSettings { acsMaxAge = 0 }
      cookieValue <- loginRequest
        >>= liftIO . forgeCookies ss newAuthSettings ssServerKeySet
      let t = UTCTime (toEnum 0) 0
      getPrivate cookieValue `shouldRespondWithException` (CookieExpired t t)


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
  let exception = BSLC8.pack . head . words . show $ ex
  (shrinkBody (BSLC8.length exception) <$> req) `shouldRespondWith` 403 {
      matchBody = matchBody' exception
    }

shouldRespondWithMarkup :: WaiSession SResponse -> Markup -> WaiExpectation
shouldRespondWithMarkup req markup = do
  req `shouldRespondWith` 200 {
      matchBody = matchBody' $ renderMarkup markup
    }

formContentType :: Header
formContentType = (
    hContentType
  , renderHeader $ contentType (Proxy :: Proxy FormUrlEncoded))

login :: String -> String -> WaiSession SResponse
login lfUsername lfPassword = request
  methodPost "/login" [formContentType] (encode LoginForm {..})

getPrivate :: BS.ByteString -> WaiSession SResponse
getPrivate cookieValue = request
  methodGet "/private" [(hCookie, cookieValue)] ""

extractSession :: SpecState -> SResponse -> IO (WithMetadata Account)
extractSession SpecState {..} SResponse {..} = maybe
  (error "cookies aren't available")
  (decryptSession ssAuthSettings ssServerKeySet)
  (parseSessionResponse ssAuthSettings simpleHeaders)

forgeCookies :: (ServerKeySet k)
  => SpecState
  -> AuthCookieSettings
  -> k
  -> SResponse
  -> IO BS.ByteString
forgeCookies ss newAuthSettings newServerKeySet r = extractSession ss r
  >>= renderSession newAuthSettings (ssRandomSource ss) newServerKeySet . wmData

