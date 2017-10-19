{-# LANGUAGE CPP               #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}
{-# LANGUAGE QuasiQuotes       #-}

module Utils (
    CBCMode
  , CFBMode
  , CTRMode

  , propRoundTrip
  , genPropRoundTrip
  , groupRoundTrip

  , modifyId
  , modifyBase64
  , modifyCookie
  , modifyPayload
  , modifyMAC
  , modifyExpiration

  , checkEquals
  , checkException
  , checkSessionDeserializationFailed
  , checkIncorrectMAC
  , checkCookieExpired
  ) where

import Crypto.Cipher.Types (BlockCipher(..), Cipher(..))
import Crypto.Hash (HashAlgorithm, SHA256(..), SHA384(..), SHA512(..))
import Crypto.Random (drgNew)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Default (def)
import Data.Proxy (Proxy(..))
import Data.Serialize (Serialize)
import Data.Time (addUTCTime)
import GHC.Generics (Generic)
import Servant.Server.Experimental.Auth.Cookie
import Test.Hspec (Spec, Selector, Expectation, shouldThrow, shouldReturn)
import Test.QuickCheck (Arbitrary(..), Gen, vectorOf, oneof, choose, sized)
import Data.List (intercalate)
import Test.Hspec.QuickCheck (prop)
import Data.Typeable (Typeable, typeRep)
import Language.Haskell.TH.Syntax (Name, Type(..), Exp(..), Q)
import Data.Tagged (Tagged(..), unTagged)
import qualified Data.ByteString.Char8 as BSC8
import Control.Monad.Catch (MonadThrow (..))

#if !MIN_VERSION_base(4,8,0)
import Control.Applicative ()
#endif


data Tree a = Leaf a | Node a [Tree a] deriving (Eq, Show, Generic)

instance Serialize a => Serialize (Tree a)

instance Arbitrary a => Arbitrary (Tree a) where
  arbitrary = sized arbitraryTree

arbitraryTree :: Arbitrary a => Int -> Gen (Tree a)
arbitraryTree 0 = Leaf <$> arbitrary
arbitraryTree n = do
  l <- choose (0, n `quot` 2)
  oneof
    [ Leaf <$> arbitrary
    , Node <$> arbitrary <*> vectorOf l (arbitraryTree (n `quot` 2))]

type Updater a = a -> IO a

type Modifier c a
  =  forall k. (ServerKeySet k)
  => AuthCookieSettings
  -> RandomSource
  -> k
  -> Proxy a
  -> Updater c

type EncryptedCookieModifier a = Modifier (Tagged SerializedEncryptedCookie ByteString) a


insideBase64 :: Modifier (Tagged EncryptedCookie ByteString) a -> EncryptedCookieModifier a
insideBase64 f = \acs rs sks p x -> base64Decode x >>= fmap base64Encode . f acs rs sks p

insideSerializedCookie :: Modifier Cookie a -> EncryptedCookieModifier a
insideSerializedCookie f = insideBase64 $ \acs rs sks p x -> cerealDecode x >>= fmap cerealEncode . f acs rs sks p

insideConsistentCookie :: Modifier Cookie a -> EncryptedCookieModifier a
insideConsistentCookie f = insideSerializedCookie $ \(acs@AuthCookieSettings {..}) rs sks p c -> do
  sk <- (Tagged . fst) <$> getKeys sks
  cookiePayload' <- cookiePayload <$> f acs rs sks p c
  cookiePadding' <- mkPadding rs acsCipher cookiePayload'
  let c' = c {
          cookiePayload = cookiePayload'
        , cookiePadding = cookiePadding'
        }
  return c' { cookieMAC = mkMAC acsHashAlgorithm sk c' }

insideEncryptedCookie :: Modifier (Tagged PayloadBytes ByteString) a -> EncryptedCookieModifier a
insideEncryptedCookie f = insideConsistentCookie $ \(acs@AuthCookieSettings {..}) rs sks p (c@Cookie {..}) -> do
  sk <- (Tagged . fst) <$> getKeys sks
  key <- mkCookieKey acsCipher acsHashAlgorithm sk cookieIV
  cookiePayload' <- applyCipherAlgorithm acsDecryptAlgorithm cookieIV key cookiePayload
                >>= f acs rs sks p
                >>= applyCipherAlgorithm acsEncryptAlgorithm cookieIV key
  return c { cookiePayload = cookiePayload' }

nullify :: Tagged a ByteString -> IO (Tagged a ByteString)
nullify = return . Tagged . const BS.empty . unTagged

updatePayload :: (Tagged PayloadBytes ByteString -> IO (Tagged PayloadBytes ByteString)) -> Cookie -> IO Cookie
updatePayload f c = (f $ cookiePayload c) >>= \cookiePayload' -> return c { cookiePayload = cookiePayload' }

cerealDecode' :: (Serialize a, MonadThrow m) => Proxy a -> Tagged b ByteString -> m (PayloadWrapper a)
cerealDecode' _ = cerealDecode

cerealEncode' :: (Serialize a) => Proxy a -> PayloadWrapper a -> Tagged b ByteString
cerealEncode' _ = cerealEncode


modifyId :: EncryptedCookieModifier a
modifyId _ _ _ _ = return . id

modifyBase64 :: EncryptedCookieModifier a
modifyBase64 _ _ _ _ = return . fmap (BSC8.scanl1 (\c c' -> if c == '_' then c' else '_'))

modifyCookie :: EncryptedCookieModifier a
modifyCookie = insideBase64 $ \_ _ _ _ -> nullify

modifyPayload :: EncryptedCookieModifier a
modifyPayload = insideConsistentCookie $ \_ _ _ _ -> updatePayload nullify

modifyMAC :: EncryptedCookieModifier a
modifyMAC = insideSerializedCookie $ \_ _ _ _ -> updatePayload nullify

modifyExpiration :: (Serialize a) => EncryptedCookieModifier a
modifyExpiration = insideEncryptedCookie $ \AuthCookieSettings {..} _ _ p s -> do
  r <- cerealDecode' p s
  return $ cerealEncode' p r { pwExpiration = addUTCTime (-acsMaxAge * 2) (pwExpiration r) }


type SessionChecker a = (Show a, Eq a) => a -> IO a -> Expectation

checkEquals :: SessionChecker a
checkEquals = flip shouldReturn

checkException :: Selector AuthCookieException -> SessionChecker a
checkException e = \_ -> flip shouldThrow e

checkSessionDeserializationFailed :: SessionChecker a
checkSessionDeserializationFailed = checkException sel where
  sel :: AuthCookieException -> Bool
  sel (SessionDeserializationFailed _) = True
  sel _                                = False

checkIncorrectMAC :: SessionChecker a
checkIncorrectMAC = checkException sel where
  sel :: AuthCookieException -> Bool
  sel (IncorrectMAC _) = True
  sel _                = False

checkCookieExpired :: SessionChecker a
checkCookieExpired = checkException sel where
  sel :: AuthCookieException -> Bool
  sel (CookieExpired _ _) = True
  sel _                   = False


roundTrip
  :: (Serialize a)
  => AuthCookieSettings
  -> EncryptedCookieModifier a
  -> Proxy a
  -> a
  -> IO a
roundTrip settings modify p x = do
  rs <- mkRandomSource drgNew 1000
  sk <- mkPersistentServerKey <$> generateRandomBytes 16
  encryptSession settings rs sk def x >>= modify settings rs sk p >>= (fmap epwSession . decryptSession settings sk)


class (HashAlgorithm h) => NamedHashAlgorithm h where
  hashName :: h -> String

instance NamedHashAlgorithm SHA512 where
  hashName _ = show SHA512

instance NamedHashAlgorithm SHA384 where
  hashName _ = show SHA384

instance NamedHashAlgorithm SHA256 where
  hashName _ = show SHA256


class BlockCipherMode m where
  modeName    :: m -> String
  modeEncrypt :: (BlockCipher c) => m -> CipherAlgorithm c
  modeDecrypt :: (BlockCipher c) => m -> CipherAlgorithm c

data CBCMode
instance BlockCipherMode CBCMode where
  modeName    _ = "CBC"
  modeEncrypt _ = cbcEncrypt
  modeDecrypt _ = cbcDecrypt

data CFBMode
instance BlockCipherMode CFBMode where
  modeName    _ = "CFB"
  modeEncrypt _ = cfbEncrypt
  modeDecrypt _ = cfbDecrypt

data CTRMode
instance BlockCipherMode CTRMode where
  modeName    _ = "CTR"
  modeEncrypt _ = ctrCombine
  modeDecrypt _ = ctrCombine


mkSettings
  :: ( NamedHashAlgorithm h
     , BlockCipher c
     , BlockCipherMode m
  ) => Proxy h
    -> Proxy c
    -> Proxy m
    -> AuthCookieSettings
mkSettings h c m = (def $) $ \(AuthCookieSettings{..}) -> AuthCookieSettings {
    acsHashAlgorithm    = h
  , acsCipher           = c
  , acsEncryptAlgorithm = modeEncrypt (unProxy m)
  , acsDecryptAlgorithm = modeDecrypt (unProxy m)
  , ..}

mkTestName
  :: ( NamedHashAlgorithm h
     , BlockCipher c
     , Serialize a, Arbitrary a, Show a, Eq a, Typeable a
     , BlockCipherMode m
  ) => Proxy h
    -> Proxy c
    -> Proxy m
    -> Proxy a
    -> String
mkTestName h c m a = intercalate "_" [
    hashName   $ unProxy h
  , cipherName $ unProxy c
  , modeName   $ unProxy m
  ] ++ (" (" ++ (show . typeRep $ a) ++ ")")

propRoundTrip
  :: ( NamedHashAlgorithm h
     , BlockCipher c
     , Serialize a, Arbitrary a, Show a, Eq a, Typeable a
     , BlockCipherMode m
  ) => Proxy h
    -> Proxy c
    -> Proxy m
    -> Proxy a
    -> EncryptedCookieModifier a
    -> SessionChecker a
    -> Spec
propRoundTrip h c m a modify check = prop (mkTestName h c m a) $
  \x -> check x (roundTrip (mkSettings h c m) modify a x)


mkProxy :: Type -> Q Exp
mkProxy t = [| Proxy :: Proxy $(return t) |]

genPropRoundTrip
  :: Name  -- ^ Hash name
  -> Name  -- ^ Cipher name
  -> Name  -- ^ Block cipher mode
  -> Name  -- ^ Session type name
  -> Name  -- ^ Modifier name
  -> Name  -- ^ Checker name
  -> Q Exp -- ^ Function of type (EncryptedCookieModifier -> Spec)
genPropRoundTrip h c m a modify check = [|
  propRoundTrip
    $(mkProxy $ PromotedT h)
    $(mkProxy $ PromotedT c)
    $(mkProxy $ PromotedT m)
    $(mkProxy $ (PromotedT ''Tree) `AppT` (PromotedT a))
    $(return $ VarE modify)
    $(return $ VarE check)
  |]

groupRoundTrip :: [Q Exp] -> Q Exp
groupRoundTrip qs = [| sequence_ $(ListE <$> sequence qs) |]
