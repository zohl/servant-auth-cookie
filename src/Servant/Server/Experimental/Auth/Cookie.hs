{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE PartialTypeSignatures      #-}


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


import Control.Monad.IO.Class
import Control.Monad             (when)
import Control.Concurrent
import Data.Either (isLeft)
import Data.Maybe                (fromMaybe, fromJust, isNothing)
import Data.IORef

import GHC.TypeLits (Symbol)

import Data.ByteString              (ByteString)
import Data.ByteString.Lazy         (toStrict, fromStrict)
import Data.ByteString.Lazy.Builder (toLazyByteString)

import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS            (length, splitAt, concat, pack)
import qualified Data.ByteString.Base64 as Base64 (encode, decode)
import qualified Data.ByteString.Char8 as BS8


import Data.Serialize            (Serialize, put, get)
import Data.Serialize.Put        (runPut)
import Data.Serialize.Get        (runGet)

import Data.Time.Clock           (UTCTime, getCurrentTime, addUTCTime)
import Data.Time.Format          (defaultTimeLocale, formatTime, parseTimeM)

import Network.HTTP.Types.Header        (hCookie)
import Network.Wai                      (Request, requestHeaders)
import Servant                          (throwError)
import Servant                          (addHeader)
import Servant.API.Experimental.Auth    (AuthProtect)
import Servant.API.ResponseHeaders      (AddHeader)
import Servant.Server                   (err403, errBody, Handler)
import Servant.Server.Experimental.Auth (AuthHandler, AuthServerData, mkAuthHandler)


import Web.Cookie                (parseCookies, renderCookies)

import Crypto.Cipher.AES              (AES256)
import Crypto.Cipher.Types            (ctrCombine, IV, makeIV, Cipher(..), BlockCipher(..))
import Crypto.Error                   (maybeCryptoError)
import Crypto.Hash                    (HashAlgorithm(..))
import Crypto.Hash.Algorithms         (SHA256)
import Crypto.MAC.HMAC                (HMAC)
import qualified Crypto.MAC.HMAC as H (hmac)
import Crypto.Random                  (drgNew, DRG(..), ChaChaDRG, getSystemDRG)


data RandomSource d where
  RandomSource :: (DRG d) => IO d -> Int -> IORef (d, Int) -> RandomSource d



refreshRef :: _ -> _ -> IO ()
refreshRef mkState ref = void $ forkIO refresh where
  void f = f >> return ()
  refresh = mkState >>= atomicWriteIORef ref



mkRandomSourceState :: (DRG d) => IO d -> IO (d, Int)
mkRandomSourceState mkDRG = do
  drg <- mkDRG
  return (drg, 0)


mkRandomSource :: forall d. (DRG d) => IO d -> Int -> IO (RandomSource d)
mkRandomSource mkDRG threshold = (RandomSource mkDRG threshold)
                             <$> (mkRandomSourceState mkDRG >>= newIORef)


refreshSource :: forall d. RandomSource d -> IO ()
refreshSource (RandomSource mkDRG _ ref) = refreshRef (mkRandomSourceState mkDRG) ref



getRandomBytes :: forall d. (DRG d) => RandomSource d -> Int -> IO ByteString
getRandomBytes rs@(RandomSource _ threshold ref) n = do
    (result, bytes) <- atomicModifyIORef ref $ \(drg, bytes) -> let
      (result, drg') = randomBytesGenerate n drg
      bytes'         = bytes + n
      in ((drg', bytes'), (result, bytes'))

    when (bytes >= threshold) $ refreshSource rs
    return $! result



data ServerKey where
  ServerKey :: Maybe Int -> IORef (ByteString, UTCTime) -> ServerKey

skLength :: Int
skLength = 16


mkServerKeyState :: Maybe Int -> IO (ByteString, UTCTime)
mkServerKeyState maxAge = do
  key <- fst . randomBytesGenerate skLength <$> drgNew
  time <- addUTCTime (fromIntegral (fromMaybe 0 maxAge)) <$> getCurrentTime
  return (key, time)

mkServerKey :: Maybe Int -> IO ServerKey
mkServerKey maxAge = (ServerKey maxAge) <$> (mkServerKeyState maxAge >>= newIORef)

refreshServerKey :: ServerKey -> IO ()
refreshServerKey (ServerKey maxAge ref) = refreshRef (mkServerKeyState maxAge) ref


getServerKey :: ServerKey -> IO ByteString
getServerKey sk@(ServerKey maxAge ref) = do
  (key, time) <- readIORef ref
  currentTime <- getCurrentTime

  let expired = ($ maxAge) $ maybe
                  False
                  (\dt -> currentTime > addUTCTime (fromIntegral dt) time)

  when (expired) $ refreshServerKey sk
  return $! key


data Cookie = Cookie {
    iv         :: ByteString
  , expiration :: UTCTime
  , payload    :: ByteString
  }

expirationFormat :: String
expirationFormat = "%0Y%m%d%H%M%S"


ivSize :: Int
expirationSize :: Int
macSize :: Int

[ivSize, expirationSize, macSize] = [
    blockSize (undefined::AES256)
  , 14
  , hashDigestSize (undefined::SHA256)
  ]


hmac :: ByteString -> ByteString -> ByteString
hmac key msg = (BS.pack . BA.unpack) ((H.hmac key msg) :: HMAC SHA256)

aes :: ByteString -> ByteString -> ByteString -> ByteString
aes iv key msg = (BS.pack . BA.unpack) (ctrCombine key' iv' msg) where
  iv' = (fromMaybe (error "bad IV") (makeIV iv)) :: IV AES256
  key' = (fromMaybe (error "bad key") (maybeCryptoError $ cipherInit key)) :: AES256

splitMany :: (Int -> a -> (a, a)) -> [Int] -> a -> [a]
splitMany _ [] s = [s]
splitMany f (x:xs) s = let (chunk, rest) = f x s in chunk:(splitMany f xs rest)


-- | Encrypt given cookie with server key
encryptCookie :: ByteString -> Cookie -> ByteString
encryptCookie serverKey cookie = BS.concat [iv', expiration', payload', mac] where
  iv'         = iv cookie
  expiration' = BS8.pack . formatTime defaultTimeLocale expirationFormat $ expiration cookie
  key         = hmac serverKey $ BS.concat [iv', expiration']
  payload'    = aes iv' key (payload cookie)
  mac         = hmac serverKey $ BS.concat [iv', expiration', payload']

-- | Decrypt cookie from bytestring
decryptCookie :: ByteString -> UTCTime -> ByteString -> Either String Cookie
decryptCookie serverKey currentTime s = do
  let [iv', expiration', payload', mac'] = splitMany BS.splitAt [
          ivSize
        , expirationSize
        , (BS.length s) - ivSize - expirationSize - macSize] s

  when (mac' /= (hmac serverKey $ BS.concat [iv', expiration', payload'])) $ Left "MAC failed"

  let parsedTime = parseTimeM True defaultTimeLocale expirationFormat $ BS8.unpack expiration'
  when (isNothing parsedTime) $ Left "Wrong time format"

  let expiration'' = fromJust parsedTime
  when (currentTime >= expiration'') $ Left "Expired cookie"

  let key = hmac serverKey $ BS.concat [iv', expiration']

  Right Cookie {
      iv         = iv'
    , expiration = expiration''
    , payload    = aes iv' key payload'
    }


-- | Pack session object into a cookie
encryptSession :: (Serialize a, DRG d) => Settings d-> a -> IO ByteString
encryptSession settings session = do
  iv'         <- getRandomBytes (randomSource settings) 16
  expiration' <- addUTCTime (fromIntegral (maxAge settings)) <$> getCurrentTime
  sk          <- getServerKey (serverKey settings)

  return $ Base64.encode $ encryptCookie sk Cookie {
      iv         = iv'
    , expiration = expiration'
    , payload    = (runPut $ put session)
    }

-- | Unpack session object from a cookie
decryptSession :: (Serialize a, DRG d) => Settings d -> ByteString -> IO (Either String a)
decryptSession settings s = do
  currentTime <- getCurrentTime
  serverKey   <- getServerKey (serverKey settings)
  return $ (Base64.decode s) >>= (decryptCookie serverKey currentTime) >>= (runGet get . payload)


data Settings d = Settings {
    sessionField :: ByteString
    -- ^ Name of a cookie which stores session object

  , cookieFlags  :: [ByteString]
    -- ^ Session cookie's flags

  , maxAge       :: Int
    -- ^ How much time (in seconds) the cookie will be valid
    -- (corresponds to Max-Age attribute)

  , path         :: ByteString
    -- ^ Scope of the cookie (corresponds to Path attribute)

  , errorMessage :: String
    -- ^ Message to show in request when the cookie is invalid

  , hideReason   :: Bool
    -- ^ Whether to print reason why the cookie was rejected
    -- (if False, errorMessage will be used instead)

  , randomSource :: RandomSource d
    -- ^ TODO

  -- , threshold :: Int
  --   -- ^ How much random bytes will be used before randomSource will be reset

  , serverKey :: ServerKey
    -- ^ TODO

  -- , serverKeyMaxAge :: Maybe Int
  --   -- ^ TODO
  }


defaultSettings :: Settings _
defaultSettings = Settings {
   sessionField = "Session"
 , cookieFlags = ["HttpOnly", "Secure"]
 , maxAge = 300
 , path = "/"
 , hideReason = True
 , errorMessage = "Not authorized"
 }


type family AuthCookieData
type instance AuthServerData (AuthProtect "cookie-auth") = AuthCookieData


getSession :: forall a d. (Serialize a, DRG d) => Settings d -> Request -> IO (Either String a)
getSession settings req = formatError <$>
                            either (return . Left) (decryptSession settings) getSessionString where

  getSessionString :: Either String ByteString
  getSessionString = do
    let cookies = parseCookies <$> lookup hCookie (requestHeaders req)
    when (isNothing cookies) $ Left "No cookie header"

    let sessionStr = lookup (sessionField settings) (fromJust cookies)
    when (isNothing sessionStr) $ Left "No session cookie"
    Right $ fromJust sessionStr

  formatError :: Either String a -> Either String a
  formatError result = do
    when ((isLeft result) && (hideReason settings)) $ Left (errorMessage settings)
    result


addSession :: (MonadIO m, Serialize a, AddHeader (h::Symbol) ByteString s r, DRG d)
                => Settings d -> a -> s -> m r
addSession settings a response = do
  sessionString <- liftIO $ encryptSession settings a
  return $ addHeader (toStrict $ toLazyByteString $ renderCookies $ [
                         ((sessionField settings), sessionString)
                       , ("Path"                 , (path settings))
                       , ("Max-Age"              , BS8.pack $ show $ maxAge settings)
                       ] ++ (map (\f -> (f, "")) (cookieFlags settings))) response


defaultAuthHandler :: forall a d. (Serialize a, DRG d) => Settings d -> AuthHandler Request a
defaultAuthHandler settings = mkAuthHandler handler where

  handler :: Request -> Handler a
  handler req = (liftIO $ (getSession settings req)) >>= either
    (\err -> throwError (err403 { errBody = fromStrict $ BS8.pack err }))
    return


