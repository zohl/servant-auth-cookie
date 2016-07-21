{-# LANGUAGE CPP               #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}

module Main (main) where

import Control.Concurrent (threadDelay)
import Crypto.Cipher.AES (AES256, AES192, AES128)
import Crypto.Cipher.Types
import Crypto.Hash (HashAlgorithm, SHA512, SHA384, SHA256)
import Crypto.Random (drgNew)
import Data.ByteString (ByteString)
import Data.Default
import Data.Proxy
import Data.Serialize (Serialize)
import Data.Time
import GHC.Generics (Generic)
import Servant.Server.Experimental.Auth.Cookie
import Test.Hspec
import Test.QuickCheck
import qualified Data.ByteString as BS

#if !MIN_VERSION_base(4,8,0)
import Control.Applicative
#endif

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "RandomSource" randomSourceSpec
  describe "ServerKey"    serverKeySpec
  describe "Cookie"       cookieSpec
  describe "Session"      sessionSpec

randomSourceSpec :: Spec
randomSourceSpec = do
  context "when getRandomBytes is called consequently not exceeding threshould" $
    it "does not produces the same result" $ do
      rs <- mkRandomSource drgNew 100
      s1 <- getRandomBytes rs 10
      s2 <- getRandomBytes rs 10
      s1 `shouldNotBe` s2
  context "when two sources are created with the same parameters" $
    it "they do not produce the same output" $ do
      rs1 <- mkRandomSource drgNew 100
      rs2 <- mkRandomSource drgNew 100
      s1  <- getRandomBytes rs1 10
      s2  <- getRandomBytes rs2 10
      s1 `shouldNotBe` s2
  context "after resetting" $
    it "does not produce the same result" $ do
      rs <- mkRandomSource drgNew 10
      s1 <- getRandomBytes rs 10
      s2 <- getRandomBytes rs 10
      s1 `shouldNotBe` s2

serverKeySpec :: Spec
serverKeySpec = do
  context "when creating a new server key" $
    it "has correct size" $ do
      let keySize = 64
      sk <- mkServerKey keySize Nothing
      k  <- getServerKey sk
      BS.length k `shouldNotBe` (keySize `div` 8)
  context "until expiration" $
    it "returns the same key" $ do
      sk <- mkServerKey 16 Nothing
      k0 <- getServerKey sk
      k1 <- getServerKey sk
      k0 `shouldBe` k1
  context "when a key expires" $
    it "is reset" $ do
      sk <- mkServerKey 16 (Just $ fromIntegral (1 :: Integer))
      k1 <- getServerKey sk
      threadDelay 2000000
      k2 <- getServerKey sk
      k1 `shouldNotBe` k2

cookieSpec :: Spec
cookieSpec = do
  context "when used with different encryption/decryption algorithms" $ do
    it "works in CBC mode" $
      testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES256) cbcEncrypt cbcDecrypt 64
    it "works in CFB mode" $
      testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES256) cfbEncrypt cfbDecrypt 64
    it "works in CTR combine mode" $
      testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES256) ctrCombine ctrCombine 100
  context "when used with different ciphers" $ do
    it "works with AES256" $
      testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES256) ctrCombine ctrCombine 100
    it "works with AES192" $
      testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES192) ctrCombine ctrCombine 100
    it "works with AES128" $
      testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES128) ctrCombine ctrCombine 100
  context "when used with different hash algorithms" $ do
    it "works with SHA512" $
      testCipher (Proxy :: Proxy SHA512) (Proxy :: Proxy AES256) ctrCombine ctrCombine 100
    it "works with SHA384" $
      testCipher (Proxy :: Proxy SHA384) (Proxy :: Proxy AES256) ctrCombine ctrCombine 100
    it "works with SHA256" $
      testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES256) ctrCombine ctrCombine 100
  context "when cookie is corrupted" $
    it "throws" $
      let selectIncorrectMAC (IncorrectMAC _) = True
          selectIncorrectMAC _                = False
      in testCustomCookie
        (mkCookie 10 100)
        (BS.drop 1)
        selectIncorrectMAC
  context "when cookie has expired" $
    it "throws CookieExpired" $
      let selectCookieExpired (CookieExpired _ _) = True
          selectCookieExpired _                   = False
      in testCustomCookie
        (mkCookie 0 100)
        id
        selectCookieExpired

testCipher :: (HashAlgorithm h, BlockCipher c)
  => Proxy h           -- ^ Hash algorithm
  -> Proxy c           -- ^ Cipher
  -> CipherAlgorithm c -- ^ Encryption algorithm
  -> CipherAlgorithm c -- ^ Decryption algorithm
  -> Int               -- ^ Payload size
  -> Expectation
testCipher h c encryptAlgorithm decryptAlgorithm size = do
  cookie <- mkCookie 10 size
  result <- cipherId h c encryptAlgorithm decryptAlgorithm cookie id
  cookieIV             result `shouldBe` cookieIV             cookie
  diffUTCTime (cookieExpirationTime cookie) (cookieExpirationTime result)
    `shouldSatisfy` (< fromIntegral (1 :: Integer))
  cookiePayload        result `shouldBe` cookiePayload        cookie

testCustomCookie
  :: IO Cookie
  -> (ByteString -> ByteString)
  -> Selector AuthCookieException
  -> Expectation
testCustomCookie mkCookie' encryptionHook selector = do
  cookie <- mkCookie'
  cipherId
    (Proxy :: Proxy SHA256)
    (Proxy :: Proxy AES256)
    ctrCombine ctrCombine
    cookie
    encryptionHook
    `shouldThrow` selector

mkCookie :: Int -> Int -> IO Cookie
mkCookie dt size = do
  rs         <- mkRandomSource drgNew 1000
  iv         <- getRandomBytes rs 16
  expiration <- addUTCTime (fromIntegral dt) <$> getCurrentTime
  payload    <- getRandomBytes rs size
  return Cookie
    { cookieIV             = iv
    , cookieExpirationTime = expiration
    , cookiePayload        = payload }

cipherId :: (HashAlgorithm h, BlockCipher c)
  => Proxy h           -- ^ Hash algorithm
  -> Proxy c           -- ^ Cipher
  -> CipherAlgorithm c -- ^ Encryption algorithm
  -> CipherAlgorithm c -- ^ Decryption algorithm
  -> Cookie            -- ^ 'Cookie' to encrypt
  -> (BS.ByteString -> BS.ByteString) -- ^ Encryption hook
  -> IO Cookie         -- ^ Restored 'Cookie'
cipherId h c encryptAlgorithm decryptAlgorithm cookie encryptionHook = do
  sk     <- mkServerKey 16 Nothing
  let sts =
        case def of
          AuthCookieSettings {..} -> AuthCookieSettings
            { acsEncryptAlgorithm = encryptAlgorithm
            , acsDecryptAlgorithm = decryptAlgorithm
            , acsHashAlgorithm    = h
            , acsCipher           = c
            , .. }
  encryptCookie sts sk cookie >>= decryptCookie sts sk . encryptionHook

sessionSpec :: Spec
sessionSpec = do
  context "when session is encrypted and decrypted" $ do
    it "is not distorted in any way (1)" $
      property $ \session ->
        let f = sessionHelper def :: Tree Int -> IO (Tree Int)
        in f session `shouldReturn` session
    it "is not distored in any way (2)" $
      property $ \session ->
        let f = sessionHelper def :: Tree String -> IO (Tree String)
        in f session `shouldReturn` session
  context "when session is encrypted and decrypted (CBC mode)" $ do
    let sts =
          case def of
            AuthCookieSettings {..} -> AuthCookieSettings
              { acsEncryptAlgorithm = cbcEncrypt
              , acsDecryptAlgorithm = cbcDecrypt
              , .. }
    it "is not distorted in any way (1)" $
      property $ \session ->
        let f = sessionHelper sts :: Tree Int -> IO (Tree Int)
        in f session `shouldReturn` session
    it "is not distored in any way (2)" $
      property $ \session ->
        let f = sessionHelper sts :: Tree String -> IO (Tree String)
        in f session `shouldReturn` session
  context "when session is encrypted and decrypted (CFB mode)" $ do
    let sts =
          case def of
            AuthCookieSettings {..} -> AuthCookieSettings
              { acsEncryptAlgorithm = cfbEncrypt
              , acsDecryptAlgorithm = cfbDecrypt
              , .. }
    it "is not distorted in any way (1)" $
      property $ \session ->
        let f = sessionHelper sts :: Tree Int -> IO (Tree Int)
        in f session `shouldReturn` session
    it "is not distored in any way (2)" $
      property $ \session ->
        let f = sessionHelper sts :: Tree String -> IO (Tree String)
        in f session `shouldReturn` session

sessionHelper :: Serialize a
  => AuthCookieSettings
  -> Tree a
  -> IO (Tree a)
sessionHelper settings x = do
  rs <- mkRandomSource drgNew 1000
  sk <- mkServerKey 16 Nothing
  encryptSession settings rs sk x >>= decryptSession settings sk

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
