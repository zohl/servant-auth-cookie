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

  , propId
  , mkPropId
  , groupProps
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
import Language.Haskell.TH.Syntax (Name, Type(..), Exp(..), Q, runQ, Stmt(..))

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

roundTrip :: (Serialize a) => AuthCookieSettings -> Proxy a -> a -> IO a
roundTrip  settings _ x = do
  rs <- mkRandomSource drgNew 1000
  sk <- mkPersistentServerKey <$> generateRandomBytes 16
  encryptSession settings rs sk x >>= (fmap epwSession . decryptSession settings sk)


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


propId
  :: ( NamedHashAlgorithm h
     , BlockCipher c
     , Serialize a, Arbitrary a, Show a, Eq a, Typeable a
     , BlockCipherMode m
  ) => Proxy h
    -> Proxy c
    -> Proxy a
    -> Proxy m
    -> Spec
propId acsHashAlgorithm' acsCipher' p m
  = let settings = (def $) $ \(AuthCookieSettings{..}) -> AuthCookieSettings {
          acsHashAlgorithm = acsHashAlgorithm'
        , acsCipher = acsCipher'
        , acsEncryptAlgorithm = modeEncrypt (unProxy m)
        , acsDecryptAlgorithm = modeDecrypt (unProxy m)
        , ..}
        name = intercalate "_" [
            hashName $ unProxy acsHashAlgorithm'
          , cipherName $ unProxy acsCipher'
          , modeName (unProxy m)
          ] ++ (" (" ++ (show . typeRep $ p) ++ ")")
    in prop name $ \x -> roundTrip settings p x `shouldReturn` x


mkProxy :: Type -> Q Exp
mkProxy t = [| Proxy :: Proxy $(return t) |]

mkPropId
  :: Name -- ^ Hash name
  -> Name -- ^ Cipher name
  -> Name -- ^ Session type name
  -> Name -- ^ Block cipher mode
  -> Q Exp
mkPropId h c a m = [|
  propId
    $(mkProxy $ PromotedT h)
    $(mkProxy $ PromotedT c)
    $(mkProxy $ (PromotedT ''Tree) `AppT` (PromotedT a))
    $(mkProxy $ PromotedT m)
    |]


groupProps :: [Q Exp] -> Q Exp
groupProps = fmap (DoE . map NoBindS) . sequence
