{-# LANGUAGE CPP               #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE FlexibleContexts  #-}
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

  , checkEquals
  , checkException
  , checkSessionDeserializationFailed
  , checkIncorrectMAC
  ) where

import           Control.Concurrent                      (threadDelay)
import           Control.Monad.IO.Class                  (MonadIO, liftIO)
import           Crypto.Cipher.AES                       (AES128, AES192, AES256)
import           Crypto.Cipher.Types
import           Crypto.Hash                             (HashAlgorithm, SHA256(..),SHA384(..), SHA512(..))
import           Crypto.Random                           (drgNew)
import           Data.ByteString                         (ByteString)
import qualified Data.ByteString                         as BS
import           Data.Default
import           Data.Proxy
import           Data.Serialize                          (Serialize)
import           Data.Time
import           GHC.Generics                            (Generic)
import           Servant.Server.Experimental.Auth.Cookie
import           Test.Hspec
import           Test.QuickCheck
import Data.List (intercalate)
import Test.Hspec.QuickCheck (prop)
import Data.Typeable (Typeable, typeRep)
import Language.Haskell.TH.Syntax (Name, Type(..), Exp(..), Q, runQ, Stmt(..), newName, Pat(..))
import Data.Tagged (Tagged(..), unTagged)
import qualified Data.ByteString.Char8                         as BSC8
import Data.Monoid ((<>))

#if !MIN_VERSION_base(4,8,0)
import           Control.Applicative
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


type Modifier a
  =  forall k. (ServerKeySet k)
  => AuthCookieSettings
  -> RandomSource
  -> k
  -> a
  -> IO a

type EncryptedCookieModifier = Modifier (Tagged SerializedEncryptedCookie ByteString)


insideBase64 :: Modifier (Tagged EncryptedCookie ByteString) -> EncryptedCookieModifier
insideBase64 f = \acs rs sks x -> base64Decode x >>= fmap base64Encode . f acs rs sks

insideCookie :: Modifier Cookie -> EncryptedCookieModifier
insideCookie f = insideBase64 $ \acs rs sks x -> cerealDecode x >>= fmap cerealEncode . f acs rs sks

insidePayload :: Modifier (Tagged PayloadBytes ByteString) -> EncryptedCookieModifier
insidePayload f = insideCookie $ \(acs@AuthCookieSettings{..}) rs sks c -> do
  sk <- (Tagged . fst) <$> getKeys sks

  cookiePayload' <- f acs rs sks (cookiePayload c)
  cookiePadding' <- mkPadding rs acsCipher cookiePayload'
  let c' = c {
          cookiePayload = cookiePayload'
        , cookiePadding = cookiePadding'
        }
  let cookieMAC'= mkMAC acsHashAlgorithm sk c'

  return c' { cookieMAC = cookieMAC' }

nullify :: Tagged a ByteString -> IO (Tagged a ByteString)
nullify = return . Tagged . const BS.empty . unTagged


modifyId :: EncryptedCookieModifier
modifyId _ _ _ = return . id

modifyBase64 :: EncryptedCookieModifier
modifyBase64 _ _ _ = return . fmap (BSC8.scanl1 (\c c' -> if c == '_' then c' else '_'))

modifyCookie :: EncryptedCookieModifier
modifyCookie = insideBase64 $ \_ _ _ -> nullify

modifyPayload :: EncryptedCookieModifier
modifyPayload = insidePayload $ \_ _ _ -> nullify

modifyMAC :: EncryptedCookieModifier
modifyMAC = insideCookie $ \_ _ _ c -> return c { cookieMAC = Tagged BS.empty }


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


roundTrip
  :: (Serialize a)
  => AuthCookieSettings
  -> EncryptedCookieModifier
  -> Proxy a
  -> a
  -> IO a
roundTrip settings modify _ x = do
  rs <- mkRandomSource drgNew 1000
  sk <- mkPersistentServerKey <$> generateRandomBytes 16
  encryptSession settings rs sk x >>= modify settings rs sk >>= (fmap epwSession . decryptSession settings sk)


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
    -> EncryptedCookieModifier
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
