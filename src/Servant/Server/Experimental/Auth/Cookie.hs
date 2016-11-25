{-|
  Module:      Servant.Server.Experimental.Auth.Cookie
  Copyright:   (c) 2016 Al Zohali
  License:     BSD3
  Maintainer:  Al Zohali <zohl@fmap.me>
  Stability:   experimental

  = Description

  Authentication via encrypted client-side cookies, inspired by
  client-session library by Michael Snoyman and based on ideas of the
  paper \"A Secure Cookie Protocol\" by Alex Liu et al.
-}

{-# LANGUAGE CPP                 #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE DeriveDataTypeable  #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE KindSignatures      #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections       #-}
{-# LANGUAGE TypeFamilies        #-}

module Servant.Server.Experimental.Auth.Cookie
  ( CipherAlgorithm
  , AuthCookieData
  , Cookie (..)
  , AuthCookieException (..)

  , RandomSource
  , mkRandomSource
  , getRandomBytes

  , ServerKey
  , mkServerKey
  , mkServerKeyFromBytes
  , getServerKey

  , AuthCookieSettings (..)

  , encryptCookie
  , decryptCookie

  , encryptSession
  , decryptSession

  , addSession
  , removeSession
  , addSessionToErr
  , getSession
  
  -- exposed for testing purpose
  , renderSession
  
  , defaultAuthHandler
  ) where

import Blaze.ByteString.Builder (toByteString)
import Control.Monad
import Control.Monad.Catch (MonadThrow (..), Exception)
import Control.Monad.Except
import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types
import Crypto.Error
import Crypto.Hash (HashAlgorithm(..))
import Crypto.Hash.Algorithms (SHA256)
import Crypto.MAC.HMAC (HMAC)
import Crypto.Random (drgNew, DRG(..))
import Data.ByteString (ByteString)
import Data.Default
import Data.IORef
import Data.Maybe (fromMaybe, isNothing)
import Data.Monoid ((<>))
import Data.Proxy
import Data.Serialize
import Data.Time
import Data.Typeable
import GHC.TypeLits (Symbol)
import Network.HTTP.Types (hCookie)
import Network.Wai (Request, requestHeaders)
import Servant (addHeader, ServantErr (..))
import Servant.API.Experimental.Auth (AuthProtect)
import Servant.API.ResponseHeaders (AddHeader)
import Servant.Server (err403)
import Servant.Server.Experimental.Auth
import Web.Cookie
import qualified Crypto.MAC.HMAC        as H
import qualified Data.ByteArray         as BA
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Char8  as BSC8

#if !MIN_VERSION_base(4,8,0)
import Control.Applicative
#endif

----------------------------------------------------------------------------
-- General types

-- | A type for encryption and decryption functions operating on 'ByteString's.
type CipherAlgorithm c = c -> IV c -> ByteString -> ByteString

-- | A type family that maps user-defined data to 'AuthServerData'.
type family AuthCookieData
type instance AuthServerData (AuthProtect "cookie-auth") = AuthCookieData

-- | Cookie representation.
data Cookie = Cookie
  { cookieIV             :: ByteString -- ^ The initialization vector
  , cookieExpirationTime :: UTCTime    -- ^ The cookie's expiration time
  , cookiePayload        :: ByteString -- ^ The payload
  } deriving (Eq, Show)

-- | The exception is thrown when something goes wrong with this package.

data AuthCookieException
  = CannotMakeIV ByteString
    -- ^ Could not make 'IV' for block cipher.
  | BadProperKey CryptoError
    -- ^ Could not initialize a cipher context.
  | TooShortProperKey Int Int
    -- ^ The key is too short for current cipher algorithm. Arguments of
    -- this constructor: minimal key length, actual key length.
  | IncorrectMAC ByteString
    -- ^ Thrown when Message Authentication Code (MAC) is not correct.
  | CannotParseExpirationTime ByteString
    -- ^ Thrown when expiration time cannot be parsed.
  | CookieExpired UTCTime UTCTime
    -- ^ Thrown when 'Cookie' has expired. Arguments of the constructor:
    -- expiration time, actual time.
  | SessionDeserializationFailed String
    -- ^ This is thrown when 'runGet' or 'Base64.decode' blows up.
  deriving (Eq, Show, Typeable)

instance Exception AuthCookieException

----------------------------------------------------------------------------
-- Random source

-- | A wrapper of self-resetting 'DRG' suitable for concurrent usage.
data RandomSource where
  RandomSource :: DRG d => IO d -> Int -> IORef (d, Int) -> RandomSource

-- | Constructor for 'RandomSource' value.
mkRandomSource :: (MonadIO m, DRG d)
  => IO d              -- ^ How to get deterministic random generator
  -> Int -- ^ Threshold (number of bytes to be generated before resetting)
  -> m RandomSource -- ^ New 'RandomSource' value
mkRandomSource mkDRG threshold =
  RandomSource mkDRG threshold `liftM` liftIO ((,0) <$> mkDRG >>= newIORef)

-- | Extract pseudo-random bytes from 'RandomSource'.
getRandomBytes :: MonadIO m
  => RandomSource      -- ^ The source of random numbers
  -> Int               -- ^ How many random bytes to generate
  -> m ByteString      -- ^ The generated bytes in form of a 'ByteString'
getRandomBytes (RandomSource mkDRG threshold ref) n = do
  freshDRG <- liftIO mkDRG
  liftIO . atomicModifyIORef' ref $ \(drg, bytes) ->
    let (result, drg') = randomBytesGenerate n drg
        bytes'         = bytes + n
    in if bytes' >= threshold
         then ((freshDRG, 0), result)
         else ((drg', bytes'), result)

----------------------------------------------------------------------------
-- Server key

-- | A wrapper of self-resetting 'ByteString' of random symbols suitable for
-- concurrent usage.
data ServerKey =
  ServerKey Int (Maybe NominalDiffTime) (IORef (ByteString, UTCTime))

-- | Constructor for 'ServerKey' value.
mkServerKey :: MonadIO m
  => Int               -- ^ Size of the server key
  -> Maybe NominalDiffTime -- ^ Expiration time ('Nothing' is eternity)
  -> m ServerKey       -- ^ New 'ServerKey'
mkServerKey size maxAge =
  ServerKey size maxAge `liftM` liftIO (mkServerKeyState size maxAge >>= newIORef)

-- | Constructor for 'ServerKey' value using predefined key.
mkServerKeyFromBytes :: MonadIO m
  => ByteString     -- ^ Predefined key
  -> m ServerKey    -- ^ New 'ServerKey'
mkServerKeyFromBytes bytes =
  ServerKey (BS.length bytes) Nothing `liftM` liftIO (newIORef (bytes, timeOrigin)) 
  where
    -- we don't care about the time as the key never expires
    timeOrigin = UTCTime (toEnum 0) 0

-- | Extract value from 'ServerKey'.
getServerKey :: MonadIO m
  => ServerKey         -- ^ The 'ServerKey'
  -> m ByteString      -- ^ Its random symbol
getServerKey (ServerKey size maxAge ref) = do
  currentTime <- liftIO getCurrentTime
  (key', expirationTime') <- mkServerKeyState size maxAge
  liftIO . atomicModifyIORef' ref $ \(key, expirationTime) ->
    let expired =
          if isNothing maxAge
            then False
            else currentTime > expirationTime
    in if expired
         then ((key', expirationTime'), key')
         else ((key,  expirationTime),  key)

-- | An initializer of 'ServerKey' state.
mkServerKeyState :: MonadIO m
  => Int               -- ^ Size of the server key
  -> Maybe NominalDiffTime -- ^ Expiration time ('Nothing' is eternity)
  -> m (ByteString, UTCTime)
mkServerKeyState size maxAge = liftIO $ do
  key  <- fst . randomBytesGenerate size <$> drgNew
  time <- addUTCTime (fromMaybe 0 maxAge) <$> getCurrentTime
  return (key, time)

----------------------------------------------------------------------------
-- Settings

-- | Options that determine authentication mechanisms. Use 'def' to get
-- default value of this type.

data AuthCookieSettings where
  AuthCookieSettings :: (HashAlgorithm h, BlockCipher c) =>
    { acsSessionField :: ByteString
      -- ^ Name of a cookie which stores session object
    , acsCookieFlags :: [ByteString]
      -- ^ Session cookie's flags
    , acsMaxAge :: NominalDiffTime
      -- ^ For how long the cookie will be valid (corresponds to “Max-Age”
      -- attribute).
    , acsExpirationFormat :: String
      -- ^ Expiration format as in 'formatTime'.
    , acsPath :: ByteString
      -- ^ Scope of the cookie (corresponds to “Path” attribute).
    , acsHashAlgorithm :: Proxy h
      -- ^ Hash algorithm that will be used in 'hmac'.
    , acsCipher :: Proxy c
      -- ^ Symmetric cipher that will be used in encryption.
    , acsEncryptAlgorithm :: CipherAlgorithm c
      -- ^ Algorithm to encrypt cookies.
    , acsDecryptAlgorithm :: CipherAlgorithm c
      -- ^ Algorithm to decrypt cookies.
    } -> AuthCookieSettings

instance Default AuthCookieSettings where
  def = AuthCookieSettings
    { acsSessionField = "Session"
    , acsCookieFlags  = ["HttpOnly", "Secure"]
    , acsMaxAge       = fromIntegral (12 * 3600 :: Integer) -- 12 hours
    , acsExpirationFormat = "%0Y%m%d%H%M%S"
    , acsPath         = "/"
    , acsHashAlgorithm = Proxy :: Proxy SHA256
    , acsCipher       = Proxy :: Proxy AES256
    , acsEncryptAlgorithm = ctrCombine
    , acsDecryptAlgorithm = ctrCombine }

----------------------------------------------------------------------------
-- Encrypt/decrypt cookie

-- | Encrypt given 'Cookie' with server key.
--
-- The function can throw the following exceptions (of type
-- 'AuthCookieException'):
--
--     * 'TooShortProperKey'
--     * 'CannotMakeIV'
--     * 'BadProperKey'
encryptCookie :: (MonadIO m, MonadThrow m)
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> ServerKey         -- ^ 'ServerKey' to use
  -> Cookie            -- ^ The 'Cookie' to encrypt
  -> m ByteString      -- ^ Encrypted 'Cookie' is form of 'ByteString'
encryptCookie AuthCookieSettings {..} sk cookie = do
  let iv = cookieIV cookie
      expiration = BSC8.pack $ formatTime
        defaultTimeLocale
        acsExpirationFormat
        (cookieExpirationTime cookie)
  serverKey <- getServerKey sk
  key <- mkProperKey
    (cipherKeySize $ unProxy acsCipher)
    (sign acsHashAlgorithm serverKey $ iv <> expiration)
  payload <- applyCipherAlgorithm acsEncryptAlgorithm
    iv key (cookiePayload cookie)
  let mac = sign acsHashAlgorithm serverKey
        (BS.concat [iv, expiration, payload])
  return . runPut $ do
    putByteString iv
    putByteString expiration
    putByteString payload
    putByteString mac

-- | Decrypt a 'Cookie' from 'ByteString'.
--
-- The function can throw the following exceptions (of type
-- 'AuthCookieException'):
--
--     * 'TooShortProperKey'
--     * 'CannotMakeIV'
--     * 'BadProperKey'
--     * 'IncorrectMAC'
--     * 'CannotParseExpirationTime'
--     * 'CookieExpired'
decryptCookie :: (MonadIO m, MonadThrow m)
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> ServerKey         -- ^ 'ServerKey' to use
  -> ByteString        -- ^ The 'ByteString' to decrypt
  -> m Cookie          -- ^ The decrypted 'Cookie'
decryptCookie AuthCookieSettings {..} sk s = do
  currentTime <- liftIO getCurrentTime
  let ivSize  = blockSize (unProxy acsCipher)
      expSize =
        length (formatTime defaultTimeLocale acsExpirationFormat currentTime)
      payloadSize = BS.length s - ivSize - expSize -
        hashDigestSize (unProxy acsHashAlgorithm)
      butMacSize = ivSize + expSize + payloadSize
      (iv,            s0) = BS.splitAt ivSize s
      (expirationRaw, s1) = BS.splitAt expSize s0
      (payloadRaw,   mac) = BS.splitAt payloadSize s1
  serverKey <- getServerKey sk
  when (mac /= sign acsHashAlgorithm serverKey (BS.take butMacSize s)) $
    throwM (IncorrectMAC mac)
  expirationTime <-
    maybe (throwM $ CannotParseExpirationTime expirationRaw) return $
      parseTimeM False defaultTimeLocale acsExpirationFormat
        (BSC8.unpack expirationRaw)
  when (currentTime >= expirationTime) $
    throwM (CookieExpired expirationTime currentTime)
  key <- mkProperKey
    (cipherKeySize (unProxy acsCipher))
    (sign acsHashAlgorithm serverKey $ BS.take (ivSize + expSize) s)
  payload <- applyCipherAlgorithm acsDecryptAlgorithm iv key payloadRaw
  return Cookie
    { cookieIV             = iv
    , cookieExpirationTime = expirationTime
    , cookiePayload        = payload }

----------------------------------------------------------------------------
-- Encrypt/decrypt session

-- | Pack session object into a cookie. The function can throw the same
-- exceptions as 'encryptCookie'.
encryptSession :: (MonadIO m, MonadThrow m, Serialize a)
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> RandomSource      -- ^ Random source to use
  -> ServerKey         -- ^ 'ServerKey' to use
  -> a                 -- ^ Session value
  -> m ByteString     -- ^ Serialized and encrypted session
encryptSession acs@AuthCookieSettings {..} randomSource sk session = do
  iv <- getRandomBytes randomSource (blockSize $ unProxy acsCipher)
  expirationTime <- liftM (addUTCTime acsMaxAge) (liftIO getCurrentTime)
  let payload = runPut (put session)
  padding <-
    let bs = blockSize (unProxy acsCipher)
        n  = BS.length payload
        l  = (bs - (n `rem` bs)) `rem` bs
    in getRandomBytes randomSource l
  Base64.encode `liftM` encryptCookie acs sk (Cookie
    { cookieIV             = iv
    , cookieExpirationTime = expirationTime
    , cookiePayload        = BS.concat [payload, padding] })

-- | Unpack session value from a cookie. The function can throw the same
-- exceptions as 'decryptCookie'.
decryptSession :: (MonadIO m, MonadThrow m, Serialize a)
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> ServerKey         -- ^ 'ServerKey' to use
  -> ByteString        -- ^ Cookie in binary form
  -> m a               -- ^ Unpacked session value
decryptSession acs@AuthCookieSettings {..} sk s =
  let fromRight = either (throwM . SessionDeserializationFailed) return
  in fromRight (Base64.decode s) >>=
     decryptCookie acs sk        >>=
     fromRight . runGet get . cookiePayload

----------------------------------------------------------------------------
-- Add/remove session

-- | Add cookie header to response. The function can throw the same
-- exceptions as 'encryptSession'.
addSession
  :: ( MonadIO m
     , MonadThrow m
     , Serialize a
     , AddHeader (e :: Symbol) ByteString s r )
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> RandomSource     -- ^ Random source to use
  -> ServerKey         -- ^ 'ServerKey' to use
  -> a                 -- ^ The session value
  -> s                 -- ^ Response to add session to
  -> m r               -- ^ Response with the session added
addSession acs rs sk sessionData response = do
  header <- renderSession acs rs sk sessionData
  return (addHeader header response)

-- |  "Remove" a session by invalidating the cookie.
-- Cookie expiry date is set at 0  and content is wiped
removeSession  :: ( MonadIO m
                  , MonadThrow m
                  , AddHeader (e :: Symbol) ByteString s r )
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> s                 -- ^ Response to return with  session removed
  -> m r               -- ^ Response with the session "removed"
removeSession acs@AuthCookieSettings{..} response = 
  let invalidDate = BSC8.pack $ formatTime
        defaultTimeLocale
        acsExpirationFormat
        timeOrigin
      timeOrigin = UTCTime (toEnum 0) 0
      cookies =
        (acsSessionField, "") :
        ("Path",    acsPath) :
        ("Expires", invalidDate) :
        ((,"") <$> acsCookieFlags)
      header = (toByteString . renderCookies) cookies
   in return (addHeader header response)

-- | Add cookie session to error allowing to set cookie even if response is
-- not 200.

addSessionToErr
  :: ( MonadIO m
     , MonadThrow m
     , Serialize a )
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> RandomSource      -- ^ Random source to use
  -> ServerKey         -- ^ 'ServerKey' to use
  -> a                 -- ^ The session value
  -> ServantErr        -- ^ Servant error to add the cookie to
  -> m ServantErr
addSessionToErr acs rs sk sessionData err = do
  header <- renderSession acs rs sk sessionData
  return err { errHeaders = ("set-cookie", header) : errHeaders err }

-- | Request handler that checks cookies. If 'Cookie' is just missing, you
-- get 'Nothing', but if something is wrong with its format, 'getSession'
-- can throw the same exceptions as 'decryptSession'.
getSession :: (MonadIO m, MonadThrow m, Serialize a)
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> ServerKey         -- ^ 'ServerKey' to use
  -> Request           -- ^ The request
  -> m (Maybe a)       -- ^ The result
getSession acs@AuthCookieSettings {..} sk request = do
  let cookies = parseCookies <$> lookup hCookie (requestHeaders request)
      sessionBinary = cookies >>= lookup acsSessionField
  maybe (return Nothing) (liftM Just . decryptSession acs sk) sessionBinary

-- | Render session cookie to 'ByteString'.
renderSession
  :: ( MonadIO m
     , MonadThrow m
     , Serialize a )
  => AuthCookieSettings
  -> RandomSource
  -> ServerKey
  -> a
  -> m ByteString
renderSession acs@AuthCookieSettings {..} rs sk sessionData = do
  sessionBinary <- encryptSession acs rs sk sessionData
  let cookies =
        (acsSessionField, sessionBinary) :
        ("Path",    acsPath) :
        ("Max-Age", (BSC8.pack . show . n) acsMaxAge) :
        ((,"") <$> acsCookieFlags)
      n = floor :: NominalDiffTime -> Int
  (return . toByteString . renderCookies) cookies

----------------------------------------------------------------------------
-- Default auth handler

-- | Cookie authentication handler.
defaultAuthHandler :: Serialize a
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> ServerKey         -- ^ 'ServerKey' to use
  -> AuthHandler Request a -- ^
defaultAuthHandler acs sk = mkAuthHandler $ \request -> do
  msession <- liftIO (getSession acs sk request)
  maybe (throwError err403) return msession

----------------------------------------------------------------------------
-- Helpers

-- | Applies 'H.hmac' algorithm to given data.
sign :: forall h. HashAlgorithm h
  => Proxy h           -- ^ The hash algorithm to use
  -> ByteString        -- ^
  -> ByteString
  -> ByteString
sign Proxy key msg = BA.convert (H.hmac key msg :: HMAC h)
{-# INLINE sign #-}

-- | Truncates given 'ByteString' according to 'KeySizeSpecifier' or raises
-- | error if the key is not long enough.
mkProperKey :: MonadThrow m
  => KeySizeSpecifier  -- ^ Key size specifier
  -> ByteString        -- ^ The 'ByteString' to truncate
  -> m ByteString      -- ^ The resulting 'ByteString'
mkProperKey kss s = do
  let klen = BS.length s
      giveUp l = throwM (TooShortProperKey l klen)
  plen <- case kss of
    KeySizeRange l r ->
      if klen < l
        then giveUp l
        else return (min klen r)
    KeySizeEnum ls ->
      case filter (<= klen) ls of
        [] -> giveUp (minimum ls)
        xs -> return (maximum xs)
    KeySizeFixed l ->
      if klen < l
        then giveUp l
        else return l
  return (BS.take plen s)

-- | Applies given encryption or decryption algorithm to given data.
applyCipherAlgorithm :: forall c m. (BlockCipher c, MonadThrow m)
  => CipherAlgorithm c -- ^ The cipher algorithm to apply
  -> ByteString        -- ^ 'ByteString' from which to create 'IV'
  -> ByteString        -- ^ Proper key
  -> ByteString        -- ^ Cookie payload
  -> m ByteString      -- ^ The resulting 'ByteString'
applyCipherAlgorithm f ivRaw keyRaw msg = do
  iv <- case makeIV ivRaw :: Maybe (IV c) of
    Nothing -> throwM (CannotMakeIV ivRaw)
    Just  x -> return x
  key <- case cipherInit keyRaw :: CryptoFailable c of
    CryptoFailed err -> throwM (BadProperKey err)
    CryptoPassed   x -> return x
  (return . BA.convert) (f key iv msg)

-- | Return bottom of type provided as 'Proxy' tag.

unProxy :: Proxy a -> a
unProxy Proxy = undefined
