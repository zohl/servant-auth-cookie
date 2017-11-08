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
{-# LANGUAGE RankNTypes          #-}

module Servant.Server.Experimental.Auth.Cookie
  ( CipherAlgorithm
  , AuthCookieData
  , Cookie (..)
  , AuthCookieException (..)

  , WithMetadata (..)
#if MIN_VERSION_servant(0,9,1)
  , Cookied
  , cookied
#endif

  , RandomSource
  , mkRandomSource
  , getRandomBytes
  , generateRandomBytes

  , ServerKey
  , ServerKeySet (..)

  , PersistentServerKey
  , mkPersistentServerKey

  , RenewableKeySet
  , RenewableKeySetHooks (..)
  , mkRenewableKeySet

  , AuthCookieSettings (..)

  , EncryptedSession (..)
  , emptyEncryptedSession

  , encryptCookie
  , decryptCookie

  , encryptSession
  , decryptSession

  , addSession
  , removeSession
  , addSessionToErr
  , removeSessionFromErr
  , getSession

  , defaultAuthHandler

  -- exposed for testing purpose
  , renderSession
  , parseSessionRequest
  , parseSessionResponse
  ) where

import Blaze.ByteString.Builder (toByteString)
import Control.Arrow ((&&&), first)
import Control.Monad
import Control.Monad.Catch (MonadThrow (..), Exception)
import Control.Monad.Except
import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types
import Crypto.Error
import Crypto.Hash (HashAlgorithm(..))
import Crypto.Hash.Algorithms (SHA256)
import Crypto.MAC.HMAC (HMAC)
import Crypto.Random (DRG(..), drgNew)
import Data.ByteString (ByteString)
import Data.Default
import Data.IORef
import Data.List (partition)
import Data.Maybe (listToMaybe)
import Data.Monoid ((<>))
import Data.Proxy
import Data.Serialize
import Data.Time
import Data.Tagged (Tagged (..), retag)
import Data.Typeable
import GHC.TypeLits (Symbol)
import Network.HTTP.Types (hCookie, HeaderName, RequestHeaders, ResponseHeaders)
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
import qualified Network.HTTP.Types as N(Header)

#if !MIN_VERSION_base(4,8,0)
import Control.Applicative
#endif

#if MIN_VERSION_servant(0,9,0)
import Servant (ToHttpApiData (..))
#else
import Data.ByteString.Conversion (ToByteString (..))
#endif

#if MIN_VERSION_servant(0,9,1)
import Servant (noHeader, Handler)
import Servant.API.ResponseHeaders (Headers)
import qualified Servant.API.Header as S(Header)
#endif

#if MIN_VERSION_http_types(0,10,0)
import Network.HTTP.Types.Header (hSetCookie)
#endif

#if MIN_VERSION_http_types(0,10,0)
#else
hSetCookie :: HeaderName
hSetCookie = "Set-Cookie"
#endif

----------------------------------------------------------------------------
-- General types

-- | A type for encryption and decryption functions operating on 'ByteString's.
type CipherAlgorithm c = c -> IV c -> ByteString -> ByteString

-- | A type family that maps user-defined data to 'AuthServerData'.
type family AuthCookieData

-- | Wrapper for cookies and sessions to keep some related metadata.
data WithMetadata a = WithMetadata
  { wmData  :: a     -- ^ Value itself
  , wmRenew :: Bool  -- ^ Whether we should renew cookies/session
  }

type instance AuthServerData (AuthProtect "cookie-auth") = WithMetadata AuthCookieData

-- | Cookie representation.
data Cookie = Cookie
  { cookieIV             :: ByteString -- ^ The initialization vector
  , cookieExpirationTime :: UTCTime    -- ^ The cookie's expiration time
  , cookiePayload        :: ByteString -- ^ The payload
  } deriving (Eq, Show)

-- | A newtype wrapper over 'ByteString'
newtype EncryptedSession = EncryptedSession ByteString
  deriving (Eq, Show, Typeable)

-- | An empty 'EncryptedSession'
emptyEncryptedSession :: EncryptedSession
emptyEncryptedSession = EncryptedSession ""

#if MIN_VERSION_servant(0,9,0)
instance ToHttpApiData EncryptedSession where
  toHeader (EncryptedSession s) = s
  toUrlPiece = error "toUrlPiece @EncryptedSession: not implemented"
#else
instance ToByteString EncryptedSession where
  builder (EncryptedSession s) = builder s
#endif

#if MIN_VERSION_servant(0,9,1)
-- | Helper type to wrap endpoints.
type Cookied a = Headers '[S.Header "Set-Cookie" EncryptedSession] a
#endif

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
-- Tags for various bytestrings

-- | Tag encrypted cookie
data EncryptedCookie

-- | Tag for base64 serialized and encrypted cookie
data SerializedEncryptedCookie

base64Encode :: Tagged EncryptedCookie ByteString -> Tagged SerializedEncryptedCookie ByteString
base64Encode = retag . fmap Base64.encode

base64Decode
  :: Tagged SerializedEncryptedCookie ByteString
  -> Either String (Tagged EncryptedCookie ByteString)
base64Decode = fmap Tagged . Base64.decode . unTagged

----------------------------------------------------------------------------
-- Random source

-- | A wrapper of self-resetting 'DRG' suitable for concurrent usage.
data RandomSource where
  RandomSource :: DRG d => IO d -> Int -> IORef (d, Int) -> RandomSource

-- | Constructor for 'RandomSource' value.
mkRandomSource :: (MonadIO m, DRG d)
  => IO d           -- ^ How to get deterministic random generator
  -> Int            -- ^ Threshold (number of bytes to be generated before resetting)
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

-- | Internal representation of a server key.
type ServerKey = ByteString

-- | Interface for a set of server keys.
class ServerKeySet k where
  getKeys   :: (MonadThrow m, MonadIO m) => k -> m (ServerKey, [ServerKey])
  -- ^ Retrieve current and rotated keys respectively.

  removeKey :: (MonadThrow m, MonadIO m) => k -> ServerKey -> m ()
  -- ^ Non-graciously remove the key from a keyset.


-- | A keyset containing only one key, that doesn't change.
data PersistentServerKey = PersistentServerKey
  { pskBytes :: ServerKey }

instance ServerKeySet PersistentServerKey where
  getKeys     = return . (,[]) . pskBytes
  removeKey _ = error "removeKey @PersistentServerKey: not implemented"

-- | Create instance of 'PersistentServerKey'.
mkPersistentServerKey :: ByteString -> PersistentServerKey
mkPersistentServerKey bytes = PersistentServerKey { pskBytes = bytes }


-- | Customizable actions for 'RenewableKeySet'.
data RenewableKeySetHooks s p = RenewableKeySetHooks
  { rkshNewState :: forall m. (MonadIO m, MonadThrow m)
    => p                  -- KeySet parameters
    -> ([ServerKey], s)   -- Current state
    -> m ([ServerKey], s) -- New state
    -- ^ Called when a keyset needs to refresh it's state. It's result might be
    -- discarded occasionally in favour of result yielded in another thread.

  , rkshNeedUpdate :: forall m. (MonadIO m, MonadThrow m)
    => p                 -- KeySet parameters
    -> ([ServerKey], s)  -- Current state
    -> m Bool            -- Whether to update the state
    -- ^ Called before retrieving the keys and refreshing the state.

  , rkshRemoveKey :: forall m. (MonadIO m, MonadThrow m)
    => p          -- KeySet parameters
    -> ServerKey  -- Key to remove
    -> m ()       -- Action to perform
    -- ^ Called after removing the key. This hook is called only if the key
    -- belongs to a keyset and called once per key. The only purpose of it is
    -- to clear the garbage after removing the key. The state might differs
    -- after removing the key and before calling the hook, therefore the hook
    -- doesn't rely on the state.
  }


-- | Customizable key set, that provides partial implementation of
-- 'ServerKeySet'.
data RenewableKeySet s p = RenewableKeySet
  { rksState      :: IORef ([ServerKey], s)
    -- ^ Key set state (keys and user-defined state).

  , rksParameters :: p
    -- ^ User-defined parameters of the key set.

  , rksHooks      :: RenewableKeySetHooks s p
    -- ^ USer-defined hooks of the key set.
  }

instance (Eq s) => ServerKeySet (RenewableKeySet s p) where
  getKeys RenewableKeySet {..} = getKeys' rksHooks where
    getKeys' RenewableKeySetHooks {..} = do
      state <- liftIO $ readIORef rksState
      rkshNeedUpdate rksParameters state
        >>= \needUpdate -> if not needUpdate
          then return $ toResult state
          else do
            state' <- rkshNewState rksParameters state
            liftIO $ atomicModifyIORef' rksState $ \state'' -> id &&& toResult $
              if (userState state /= userState state'')
              then state''
              else state'
    toResult = (head &&& tail) . fst
    userState = snd

  removeKey RenewableKeySet {..} key = do
    found <- liftIO $ atomicModifyIORef' rksState $ \(keys, s) -> let
      (found, keys') = first (not . null) . partition (== key) $ keys
      in ((keys', s), found)
    when found $ (rkshRemoveKey rksHooks) rksParameters key

-- | Create instance of 'RenewableKeySet'.
mkRenewableKeySet :: (MonadIO m)
  => RenewableKeySetHooks s p -- ^ Hooks
  -> p                        -- ^ Parameters
  -> s                        -- ^ Initial state
  -> m (RenewableKeySet s p)
mkRenewableKeySet rksHooks rksParameters userState = liftIO $ do
  rksState <- newIORef ([], userState)
  return RenewableKeySet {..}


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
encryptCookie :: (MonadIO m, MonadThrow m, ServerKeySet k)
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> k                  -- ^ Instance of 'ServerKeySet' to use
  -> Cookie             -- ^ The 'Cookie' to encrypt
  -> m (Tagged EncryptedCookie ByteString)  -- ^ Encrypted 'Cookie' is form of 'ByteString'
encryptCookie AuthCookieSettings {..} sks cookie = do
  let iv = cookieIV cookie
      expiration = BSC8.pack $ formatTime
        defaultTimeLocale
        acsExpirationFormat
        (cookieExpirationTime cookie)
  (serverKey, _) <- getKeys sks
  key <- mkProperKey
    (cipherKeySize $ unProxy acsCipher)
    (sign acsHashAlgorithm serverKey $ iv <> expiration)
  payload <- applyCipherAlgorithm acsEncryptAlgorithm
    iv key (cookiePayload cookie)
  let mac = sign acsHashAlgorithm serverKey
        (BS.concat [iv, expiration, payload])
  return . Tagged . runPut $ do
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
decryptCookie :: (MonadIO m, MonadThrow m, ServerKeySet k)
  => AuthCookieSettings                 -- ^ Options, see 'AuthCookieSettings'
  -> k                                  -- ^ Instance of 'ServerKeySet' to use
  -> Tagged EncryptedCookie ByteString  -- ^ The 'ByteString' to decrypt
  -> m (WithMetadata Cookie)            -- ^ The decrypted 'Cookie'
decryptCookie AuthCookieSettings {..} sks (Tagged s) = do
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
      checkMac sk = mac == sign acsHashAlgorithm sk (BS.take butMacSize s)

  (currentKey, rotatedKeys) <- getKeys sks
  (serverKey, renew) <- if checkMac currentKey
    then return (currentKey, False)
    else liftM (,True) $ maybe
      (throwM $ IncorrectMAC mac)
      (return)
      (listToMaybe . map fst . filter snd . map (id &&& checkMac) $ rotatedKeys)

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
  let cookie = Cookie
        { cookieIV             = iv
        , cookieExpirationTime = expirationTime
        , cookiePayload        = payload }
  return WithMetadata
    { wmData = cookie
    , wmRenew = renew
    }

----------------------------------------------------------------------------
-- Encrypt/decrypt session

-- | Pack session object into a cookie. The function can throw the same
-- exceptions as 'encryptCookie'.
encryptSession :: (MonadIO m, MonadThrow m, Serialize a, ServerKeySet k)
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> RandomSource       -- ^ Random source to use
  -> k                  -- ^ Instance of 'ServerKeySet' to use
  -> a                  -- ^ Session value
  -> m (Tagged SerializedEncryptedCookie ByteString)  -- ^ Serialized and encrypted session
encryptSession acs@AuthCookieSettings {..} randomSource sk session = do
  iv <- getRandomBytes randomSource (blockSize $ unProxy acsCipher)
  expirationTime <- liftM (addUTCTime acsMaxAge) (liftIO getCurrentTime)
  let payload = runPut (put session)
  padding <-
    let bs = blockSize (unProxy acsCipher)
        n  = BS.length payload
        l  = (bs - (n `rem` bs)) `rem` bs
    in getRandomBytes randomSource l
  base64Encode `liftM` encryptCookie acs sk (Cookie
    { cookieIV             = iv
    , cookieExpirationTime = expirationTime
    , cookiePayload        = BS.concat [payload, padding] })

-- | Unpack session value from a cookie. The function can throw the same
-- exceptions as 'decryptCookie'.
decryptSession :: (MonadIO m, MonadThrow m, Serialize a, ServerKeySet k)
  => AuthCookieSettings                           -- ^ Options, see 'AuthCookieSettings'
  -> k                                            -- ^ Instance of 'ServerKeySet' to use
  -> Tagged SerializedEncryptedCookie ByteString  -- ^ Cookie in binary form
  -> m (WithMetadata a)                           -- ^ Unpacked session value
decryptSession acs@AuthCookieSettings {..} sks s =
  let fromRight = either (throwM . SessionDeserializationFailed) return
  in fromRight (base64Decode s) >>=
     decryptCookie acs sks      >>=
     \w -> do
        session <- fromRight . runGet get . cookiePayload $ wmData w
        return w { wmData = session }

----------------------------------------------------------------------------
-- Add/remove session

-- | Add cookie header to response. The function can throw the same
-- exceptions as 'encryptSession'.
addSession
  :: ( MonadIO m
     , MonadThrow m
     , Serialize a
     , AddHeader (e :: Symbol) EncryptedSession s r
     , ServerKeySet k )
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> RandomSource       -- ^ Random source to use
  -> k                  -- ^ Instance of 'ServerKeySet' to use
  -> a                  -- ^ The session value
  -> s                  -- ^ Response to add session to
  -> m r                -- ^ Response with the session added
addSession acs rs sk sessionData response = do
  header <- renderSession acs rs sk sessionData
  return (addHeader (EncryptedSession header) response)

-- |  "Remove" a session by invalidating the cookie.
removeSession  :: ( Monad m,
                    AddHeader (e :: Symbol) EncryptedSession s r )
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> s                 -- ^ Response to return with  session removed
  -> m r               -- ^ Response with the session "removed"
removeSession acs response =
  return (addHeader (EncryptedSession $ expiredCookie acs) response)

-- | Add cookie session to error allowing to set cookie even if response is
-- not 200.

addSessionToErr
  :: ( MonadIO m
     , MonadThrow m
     , Serialize a
     , ServerKeySet k )
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> RandomSource       -- ^ Random source to use
  -> k                  -- ^ Instance of 'ServerKeySet' to use
  -> a                  -- ^ The session value
  -> ServantErr         -- ^ Servant error to add the cookie to
  -> m ServantErr
addSessionToErr acs rs sk sessionData err = do
  header <- renderSession acs rs sk sessionData
  return err { errHeaders = (hSetCookie, header) : errHeaders err }

-- |  "Remove" a session by invalidating the cookie.
-- Cookie expiry date is set at 0  and content is wiped
removeSessionFromErr  :: ( Monad m )
  => AuthCookieSettings -- ^ Options, see 'AuthCookieSettings'
  -> ServantErr         -- ^ Servant error to add the cookie to
  -> m ServantErr
removeSessionFromErr acs err =
  return $ err { errHeaders = (hSetCookie, expiredCookie acs) : errHeaders err }

-- | Cookie expiry date is set at 0 and content is wiped.
expiredCookie :: AuthCookieSettings -> ByteString
expiredCookie AuthCookieSettings{..} = (toByteString . renderCookies) cookies
  where
    cookies =
      (acsSessionField, "") :
      ("Path",    acsPath) :
      ("Expires", invalidDate) :
      ((,"") <$> acsCookieFlags)
    invalidDate = BSC8.pack $ formatTime
      defaultTimeLocale
      acsExpirationFormat
      timeOrigin
    timeOrigin = UTCTime (toEnum 0) 0

-- | Request handler that checks cookies. If 'Cookie' is just missing, you
-- get 'Nothing', but if something is wrong with its format, 'getSession'
-- can throw the same exceptions as 'decryptSession'.
getSession :: (MonadIO m, MonadThrow m, Serialize a, ServerKeySet k)
  => AuthCookieSettings         -- ^ Options, see 'AuthCookieSettings'
  -> k                          -- ^ 'ServerKeySet' to use
  -> Request                    -- ^ The request
  -> m (Maybe (WithMetadata a)) -- ^ The result
getSession acs@AuthCookieSettings {..} sk request = maybe
  (return Nothing)
  (liftM Just . decryptSession acs sk)
  (parseSessionRequest acs $ requestHeaders request)

parseSession
  :: AuthCookieSettings
  -> HeaderName
  -> [N.Header]
  -> Maybe (Tagged SerializedEncryptedCookie ByteString)
parseSession AuthCookieSettings {..} hdr hdrs = sessionBinary where
  cookies = parseCookies <$> lookup hdr hdrs
  sessionBinary = Tagged <$> (cookies >>= lookup acsSessionField)

-- | Parse session cookie from 'RequestHeaders'.
parseSessionRequest
  :: AuthCookieSettings
  -> RequestHeaders
  -> Maybe (Tagged SerializedEncryptedCookie ByteString)
parseSessionRequest acs hdrs = parseSession acs hCookie hdrs

-- | Parse session cookie from 'ResponseHeaders'.
parseSessionResponse
  :: AuthCookieSettings
  -> ResponseHeaders
  -> Maybe (Tagged SerializedEncryptedCookie ByteString)
parseSessionResponse acs hdrs = parseSession acs hSetCookie hdrs

-- | Render session cookie to 'ByteString'.
renderSession
  :: ( MonadIO m
     , MonadThrow m
     , Serialize a
     , ServerKeySet k )
  => AuthCookieSettings
  -> RandomSource
  -> k
  -> a
  -> m ByteString
renderSession acs@AuthCookieSettings {..} rs sk sessionData = do
  Tagged sessionBinary <- encryptSession acs rs sk sessionData
  let cookies =
        (acsSessionField, sessionBinary) :
        ("Path",    acsPath) :
        ("Max-Age", (BSC8.pack . show . n) acsMaxAge) :
        ((,"") <$> acsCookieFlags)
      n = floor :: NominalDiffTime -> Int
  (return . toByteString . renderCookies) cookies


#if MIN_VERSION_servant(0,9,1)
-- | Wrapper for an implementation of an endpoint to make it automatically
-- renew the cookies.
cookied :: (Serialize a, ServerKeySet k)
  => AuthCookieSettings                        -- ^ Options, see 'AuthCookieSettings'
  -> RandomSource                              -- ^ Random source to use
  -> k                                         -- ^ Instance of 'ServerKeySet' to use
  -> (a -> r)                                  -- ^ Implementation of an endpoint
  -> ((WithMetadata a) -> Handler (Cookied r)) -- ^ "Cookied" endpoint
cookied acs rs k f = \(WithMetadata {..}) ->
  (if wmRenew then addSession acs rs k wmData else (return . noHeader)) $ f wmData
#endif

----------------------------------------------------------------------------
-- Default auth handler

-- | Cookie authentication handler.
defaultAuthHandler :: (Serialize a, ServerKeySet k)
  => AuthCookieSettings                   -- ^ Options, see 'AuthCookieSettings'
  -> k                                    -- ^ Instance of 'ServerKeySet' to use
  -> AuthHandler Request (WithMetadata a) -- ^ The result
defaultAuthHandler acs sk = mkAuthHandler $ \request -> do
  msession <- liftIO (getSession acs sk request)
  maybe (throwError err403) return msession

----------------------------------------------------------------------------
-- Helpers

-- | Applies 'H.hmac' algorithm to given data.
sign :: forall h. HashAlgorithm h
  => Proxy h           -- ^ The hash algorithm to use
  -> ByteString        -- ^ The key
  -> ByteString        -- ^ The message
  -> ByteString        -- ^ The result
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

-- | Generates random sequence of bytes from new DRG
generateRandomBytes :: Int -> IO ByteString
generateRandomBytes size = (fst . randomBytesGenerate size <$> drgNew)

