{-# LANGUAGE CPP               #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeOperators     #-}
{-# LANGUAGE TemplateHaskell   #-}
{-# LANGUAGE QuasiQuotes       #-}

module Main (main) where

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
import Utils (mkProxy, mkPropId, blockCipherModes)
import Language.Haskell.TH.Syntax (Name, Type(..), Exp(..), Q, runQ, Stmt(..))

#if !MIN_VERSION_base(4,8,0)
import           Control.Applicative
#endif

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "RandomSource"        randomSourceSpec
  describe "PersistentServerKey" persistentServerKeySpec
  describe "RenewalKeySet"       renewalKeySetSpec
  describe "Session"             sessionSpec

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

persistentServerKeySpec :: Spec
persistentServerKeySpec = do
  context "when creating a new persistent server key" $ do
    let keySize = 64
    let getSK = mkPersistentServerKey <$> generateRandomBytes keySize
            >>= getKeys

    it "has correct size" $ do
      (k, _) <- getSK
      BS.length k `shouldNotBe` (keySize `div` 8)

    it "has no rotated keys" $ do
      (_, ks) <- getSK
      length ks `shouldBe` 0


renewalKeySetSpec :: Spec
renewalKeySetSpec = spec' where

  keySize :: Int
  keySize = 16

  rkshNewState :: (MonadIO m)
    => NominalDiffTime
    -> ([ServerKey], UTCTime)
    -> m ([ServerKey], UTCTime)
  rkshNewState _ (keys, _) = liftIO $ (,)
    <$> (fmap (:keys) $ generateRandomBytes keySize)
    <*> getCurrentTime

  rkshNeedUpdate :: (MonadIO m)
    => NominalDiffTime
    -> ([ServerKey], UTCTime)
    -> m Bool
  rkshNeedUpdate dt (_, t) = liftIO $ getCurrentTime >>= return . ((dt `addUTCTime` t) <)

  rkshRemoveKey :: (MonadIO m)
    => NominalDiffTime
    -> ServerKey
    -> m ()
  rkshRemoveKey _ _ = return ()

  spec' = do
    let makeSK = mkRenewableKeySet
          RenewableKeySetHooks {..}
          (fromIntegral (1 :: Integer))
          (UTCTime (toEnum 0) 0)

    context "when accessing a renewable key set" $ do
      it "updates the keys when needed" $ do
        sk <- makeSK

        (k, ks) <- getKeys sk
        BS.length k `shouldNotBe` 0

        (_, ks') <- threadDelay 1500000 >> getKeys sk
        ks' `shouldBe` (k:ks)

      it "doesn't update the keys when not needed" $ do
        sk <- makeSK
        k  <- getKeys sk
        k' <- getKeys sk
        k' `shouldBe` k

    context "when removing key from a renewable key set" $ do
      it "removes specified key" $ do
        sk <- makeSK
        (_, ks) <- getKeys sk >> threadDelay 1500000 >> getKeys sk
        length ks `shouldNotBe` 0

        let k = head ks
        removeKey sk k
        (_, ks') <- getKeys sk
        (k:ks') `shouldBe` ks

{-
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
  sk <- mkPersistentServerKey <$> generateRandomBytes 16

  let sts =
        case def of
          AuthCookieSettings {..} -> AuthCookieSettings
            { acsEncryptAlgorithm = encryptAlgorithm
            , acsDecryptAlgorithm = decryptAlgorithm
            , acsHashAlgorithm    = h
            , acsCipher           = c
            , .. }
  encryptCookie sts sk cookie >>= (fmap wmData . decryptCookie sts sk . fmap encryptionHook)

sessionSpec :: Spec
sessionSpec = do
  let treesOfInt = Proxy :: Proxy Int
      treesOfString = Proxy :: Proxy String

  context "when session is encrypted and decrypted" $ do
    it "is not distorted in any way (1)" $
      property $ \session -> encryptThenDecrypt treesOfInt def session `shouldReturn` session
    it "is not distored in any way (2)" $
      property $ \session -> encryptThenDecrypt treesOfString def session `shouldReturn` session
  context "when session is encrypted and decrypted (CBC mode)" $ do
    let sts = case def of
                AuthCookieSettings{..} -> AuthCookieSettings
                                          { acsEncryptAlgorithm = cbcEncrypt
                                          , acsDecryptAlgorithm = cbcDecrypt
                                          , .. }
    it "is not distorted in any way (1)" $
      property $ \session -> encryptThenDecrypt treesOfInt sts session `shouldReturn` session
    it "is not distored in any way (2)" $
      property $ \session -> encryptThenDecrypt treesOfString sts session `shouldReturn` session
  context "when session is encrypted and decrypted (CFB mode)" $ do
    let sts =
          case def of
            AuthCookieSettings {..} -> AuthCookieSettings
                                       { acsEncryptAlgorithm = cfbEncrypt
                                       , acsDecryptAlgorithm = cfbDecrypt
                                       , .. }
    it "is not distorted in any way (1)" $
      property $ \session -> encryptThenDecrypt treesOfInt sts session `shouldReturn` session
    it "is not distored in any way (2)" $
      property $ \session -> encryptThenDecrypt treesOfString sts session `shouldReturn` session

encryptThenDecrypt :: Serialize a
  => Proxy a
  -> AuthCookieSettings
  -> Tree a
  -> IO (Tree a)
encryptThenDecrypt _ settings x = do
  rs <- mkRandomSource drgNew 1000
  sk <- mkPersistentServerKey <$> generateRandomBytes 16
  encryptSession settings rs sk x >>= (fmap wmData . decryptSession settings sk)
-}



sessionSpec :: Spec
sessionSpec = do
  context "test" $ do
    $(fmap (DoE . map NoBindS) $ mapM (\(h, c) -> mkPropId h c)
      [(h, c) |
          h <- [''SHA256, ''SHA384, ''SHA512]
        , c <- [''AES128, ''AES192, ''AES256]
        ]
     )

  context "when cookie is corrupted" $
    it "throws IncorrectMAC" $ pending
  context "when cookie has expired" $
    it "throws CookieExpired" $ pending
