{-# LANGUAGE CPP               #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}
{-# LANGUAGE QuasiQuotes       #-}

module Utils (
    Tree
  , mkPropId
  , propId
  , mkProxy
  , blockCipherModes
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
import Language.Haskell.TH.Syntax (Name, Type(..), Exp(..), Q, runQ)

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

treesOfInt :: Proxy (Tree Int)
treesOfInt = Proxy

treesOfString :: Proxy (Tree String)
treesOfString = Proxy


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


data BlockCipherMode c = BlockCipherMode {
    bcmName    :: String
  , bcmEncrypt :: CipherAlgorithm c
  , bcmDecrypt :: CipherAlgorithm c
  }

blockCipherModes :: (BlockCipher c) => [BlockCipherMode c]
blockCipherModes = [
    BlockCipherMode "CBC" cbcEncrypt cbcDecrypt
  , BlockCipherMode "CFB" cfbEncrypt cfbDecrypt
  , BlockCipherMode "CTR" ctrCombine ctrCombine
  ]


propId
  :: (NamedHashAlgorithm h, BlockCipher c, Serialize a, Arbitrary a, Show a, Eq a)
  => Proxy h
  -> Proxy c
  -> Proxy a
  -> BlockCipherMode c
  -> Spec
propId acsHashAlgorithm' acsCipher' p BlockCipherMode {..}
  = let settings = (def $) $ \(AuthCookieSettings{..}) -> AuthCookieSettings {
          acsHashAlgorithm = acsHashAlgorithm'
        , acsCipher = acsCipher'
        , acsEncryptAlgorithm = bcmEncrypt
        , acsDecryptAlgorithm = bcmDecrypt
        , ..}
        name = intercalate "_" [
            hashName $ unProxy acsHashAlgorithm'
          , cipherName $ unProxy acsCipher'
          , bcmName ]

    in prop name $ \x -> roundTrip settings p x `shouldReturn` x


mkProxy :: Type -> Q Exp
mkProxy t = [| Proxy :: Proxy $(return t) |]


mkPropId
  :: Name -- ^ Hash name
  -> Name -- ^ Cipher name
  -- -> Name -- ^ Session type name
  -- -> BlockCipherMode c
  -> Q Exp
mkPropId h c = [|
  propId
    $(mkProxy $ PromotedT h)
    $(mkProxy $ PromotedT c)
    (Proxy :: Proxy (Tree Int))
    (head blockCipherModes)
    |]
