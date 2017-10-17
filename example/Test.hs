{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE TupleSections #-}

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
import Web.Cookie (parseCookies)
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

#if MIN_VERSION_servant (0,9,1) && MIN_VERSION_directory (1,2,5)
import FileKeySet (mkFileKeySet, FileKSParams(..), mkFileKey)
import Control.Arrow ((***))
import Control.Monad (void, when)
import Data.Monoid ((<>))
import Control.Exception.Base (bracket)
import Network.HTTP.Types (urlEncode)
import Test.Hspec (shouldBe, shouldSatisfy)
import System.Directory (removeDirectoryRecursive, doesDirectoryExist)
import qualified Data.ByteString.Char8 as BSC8
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A
#endif


data SpecState where
  SpecState :: (ServerKeySet k) =>
    { ssRandomSource :: RandomSource
    , ssAuthSettings :: AuthCookieSettings
    , ssServerKeySet :: k
    , ssGenerateKey  :: IO ()
    } -> SpecState


main :: IO ()
main = do
  rs <- mkRandomSource drgNew 1000

  return SpecState
    { ssRandomSource = rs
    , ssAuthSettings = authSettings
    , ssServerKeySet = mkPersistentServerKey "0123456789abcdef"
    , ssGenerateKey  = return ()
    } >>= hspec . basicSpec

#if MIN_VERSION_servant (0,9,1) && MIN_VERSION_directory (1,2,5)
  let rmDir name = doesDirectoryExist name
        >>= \exists -> when exists $ removeDirectoryRecursive name

  bracket
    (do
       let keySetDir = "./test-key-set"
       rmDir keySetDir
       return FileKSParams
         { fkspMaxKeys = 3
         , fkspKeySize = 16
         , fkspPath = keySetDir
         } >>= \fksp -> (fksp,) <$> mkFileKeySet fksp)

    (rmDir . fkspPath . fst)

    (\(fksp, ks) -> hspec . renewalSpec $ SpecState
         { ssRandomSource = rs
         , ssAuthSettings = authSettings
         , ssServerKeySet = ks
         , ssGenerateKey  = mkFileKey fksp
         })
#endif

basicSpec :: SpecState -> Spec
basicSpec ss@(SpecState {..}) = describe "basic functionality" $ with
  (return $ app ssAuthSettings ssGenerateKey ssRandomSource ssServerKeySet) $ do

  let form = LoginForm {
          lfUsername = "mr_foo"
        , lfPassword = "password1"
        , lfRemember = False
        }

  context "home page" $ do
    it "responds successfully" $ do
      get "/" `shouldRespondWithMarkup` homePage

  context "login page" $ do
    it "responds successfully" $ do
      get "/login" `shouldRespondWithMarkup` (loginPage True)

    it "shows message on incorrect login" $ do
      (login form { lfPassword = "wrong" }) `shouldRespondWithMarkup` (loginPage False)

    let hasExpirationHeaders
          = not . null
          . filter ((`elem` ["Max-Age", "Expires"]) . fst)
          . parseCookies

    it "responds with session cookies if 'Remember me' is not set" $ do
      (login form { lfRemember = False }
        >>= return . hasExpirationHeaders . getCookieValue)
        >>= liftIO . (`shouldBe` False)

    it "responds with normal cookies if `Remember me` is set" $ do
      (login form { lfRemember = True }
        >>= return . hasExpirationHeaders . getCookieValue)
        >>= liftIO . (`shouldBe` True)

  context "private page" $ do

    it "rejects requests without cookies" $ do
      get "/private" `shouldRespondWith` 403 { matchBody = matchBody' "No cookies" }

    it "accepts requests with proper cookies" $ do
      (login form
         >>= return . getCookieValue
         >>= getPrivate) `shouldRespondWith` 200

    it "accepts requests with proper cookies (sanity check)" $ do
      (login form
        >>= liftIO . forgeCookies ss authSettings ssServerKeySet
        >>= getPrivate) `shouldRespondWith` 200

    it "rejects requests with incorrect MAC" $ do
      let newServerKeySet = mkPersistentServerKey "0000000000000000"
      (login form
        >>= liftIO . forgeCookies ss authSettings newServerKeySet
        >>= getPrivate) `shouldRespondWithException` (IncorrectMAC "")

    it "rejects requests with expired cookies" $ do
      let newAuthSettings = authSettings { acsMaxAge = 0 }
      let t = UTCTime (toEnum 0) 0
      (login form
        >>= liftIO . forgeCookies ss newAuthSettings ssServerKeySet
        >>= getPrivate) `shouldRespondWithException` (CookieExpired t t)

#if MIN_VERSION_servant (0,9,1) && MIN_VERSION_directory (1,2,5)
renewalSpec :: SpecState -> Spec
renewalSpec (SpecState {..}) = describe "renewal functionality" $ with
  (return $ app ssAuthSettings ssGenerateKey ssRandomSource ssServerKeySet) $ do

  context "keys" $ do
    it "automatically creates a key" $ do
      keys <- extractKeys
      liftIO $ keys `shouldSatisfy` ((== 1) . length)

    it "adds new key" $ do
      keys <- extractKeys
      addKey
      keys' <- extractKeys
      liftIO $ keys `shouldBe` (tail keys')

    it "removes a key" $ do
      keys <- extractKeys
      remKey $ last keys
      keys' <- extractKeys
      liftIO $ keys' `shouldBe` (init keys)

  context "cookies" $ do
    let form = LoginForm {
            lfUsername = "mr_foo"
          , lfPassword = "password1"
          , lfRemember = False
          }

    it "rejects requests with deleted keys" $ do
      cookieValue <- getCookieValue <$> login form
      getPrivate cookieValue `shouldRespondWith` 200

      key <- head <$> extractKeys
      addKey >> remKey key

      getPrivate cookieValue `shouldRespondWith` 403

    it "accepts requests with old key and renews cookie" $ do
      cookieValue <- getCookieValue <$> login form
      getPrivate cookieValue `shouldRespondWith` 200

      key <- head <$> extractKeys
      addKey
      newCookieValue <- getCookieValue <$> getPrivate cookieValue

      remKey key
      getPrivate newCookieValue `shouldRespondWith` 200

    it "does not renew cookies for the newest key" $ do
      cookieValue <- getCookieValue <$> login form
      _ <- getPrivate cookieValue `shouldRespondWith` 200
      r <- getPrivate cookieValue
      liftIO $ (lookup "set-cookie" $ simpleHeaders r) `shouldBe` Nothing
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

login :: LoginForm -> WaiSession SResponse
login lf = request
  methodPost "/login" [formContentType] (encode lf)

getPrivate :: BS.ByteString -> WaiSession SResponse
getPrivate cookieValue = request
  methodGet "/private" [(hCookie, cookieValue)] ""

extractSession :: SpecState -> SResponse -> IO (ExtendedPayloadWrapper Account)
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
  >>= renderSession newAuthSettings (ssRandomSource ss) newServerKeySet . epwSession

#if MIN_VERSION_servant (0,9,1) && MIN_VERSION_directory (1,2,5)
extractKeys :: WaiSession [BS.ByteString]
extractKeys = (extractKeys' . BSL.toStrict . simpleBody) <$> get "/keys" where
  del = '#'

  (openTag, closeTag) = (id *** BS.drop 1) $ BSC8.span (/= del) $
    BSL.toStrict . renderMarkup $
      H.span H.! A.class_ "key" $ H.toHtml [del]

  shrinkBy prefix = BS.drop . BS.length $ prefix

  extractKeys' body = let
    body' = snd $ BS.breakSubstring openTag body
    (key, rest) = shrinkBy openTag *** shrinkBy closeTag $
       BS.breakSubstring closeTag body'
    in if BS.null body'
       then []
       else key:(extractKeys' rest)

addKey :: WaiSession ()
addKey = void $ get "/keys/add"

remKey :: BS.ByteString -> WaiSession ()
remKey key = void $ get $ "/keys/rem/" <> (urlEncode True $ key)
#endif

getCookieValue :: SResponse -> BSC8.ByteString
getCookieValue = fromMaybe (error "cookies aren't available")
               . lookup "set-cookie"
               . simpleHeaders
