{-# LANGUAGE CPP               #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}

module Main (main) where

import Control.Concurrent (threadDelay)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Crypto.Cipher.AES (AES128, AES192, AES256)
import Crypto.Cipher.Types ()
import Crypto.Hash (SHA256(..),SHA384(..), SHA512(..))
import Crypto.Random (drgNew)
import qualified Data.ByteString as BS
import Data.Default ()
import Data.Proxy ()
import Data.Time (UTCTime(..), NominalDiffTime, addUTCTime, getCurrentTime)
import Servant.Server.Experimental.Auth.Cookie
import Test.Hspec (Spec, context, shouldBe, shouldNotBe, it, describe, hspec)
import Test.QuickCheck ()
import Test.Hspec.QuickCheck (modifyMaxSuccess)
import Utils

#if !MIN_VERSION_base(4,8,0)
import Control.Applicative ((<*>), (<$>))
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


sessionSpec :: Spec
sessionSpec = modifyMaxSuccess (const 10) $ do
  context "when session is encrypted and decrypted"
    $(groupRoundTrip $ map (\(h, c, m, a) -> genPropRoundTrip h c m a 'modifyId 'checkEquals)
      [(h, c, m, a) |
          h <- [''SHA256, ''SHA384, ''SHA512]
        , c <- [''AES128, ''AES192, ''AES256]
        , m <- [''CBCMode, ''CFBMode, ''CTRMode]
        , a <- [''Int, ''String]
        ])

  context "when base64 encoding is erroneous"
    $(groupRoundTrip $ map (\(h, c, m, a) -> genPropRoundTrip h c m a 'modifyBase64 'checkSessionDeserializationFailed)
      [(h, c, m, a) |
          h <- [''SHA256, ''SHA384, ''SHA512]
        , c <- [''AES128, ''AES192, ''AES256]
        , m <- [''CBCMode, ''CFBMode, ''CTRMode]
        , a <- [''Int, ''String]
        ])

  context "when cereal encoding is erroneous (cookie)" $
    $(groupRoundTrip $ map (\(h, c, m, a) -> genPropRoundTrip h c m a 'modifyCookie 'checkSessionDeserializationFailed)
      [(h, c, m, a) |
          h <- [''SHA256, ''SHA384, ''SHA512]
        , c <- [''AES128, ''AES192, ''AES256]
        , m <- [''CBCMode, ''CFBMode, ''CTRMode]
        , a <- [''Int, ''String]
        ])

  context "when cereal encoding is erroneous (payload)" $
    $(groupRoundTrip $ map (\(h, c, m, a) -> genPropRoundTrip h c m a 'modifyPayload 'checkSessionDeserializationFailed)
      [(h, c, m, a) |
          h <- [''SHA256, ''SHA384, ''SHA512]
        , c <- [''AES128, ''AES192, ''AES256]
        , m <- [''CBCMode, ''CFBMode, ''CTRMode]
        , a <- [''Int, ''String]
        ])

  context "when MAC is erroneous" $
    $(groupRoundTrip $ map (\(h, c, m, a) -> genPropRoundTrip h c m a 'modifyMAC 'checkIncorrectMAC)
      [(h, c, m, a) |
          h <- [''SHA256, ''SHA384, ''SHA512]
        , c <- [''AES128, ''AES192, ''AES256]
        , m <- [''CBCMode, ''CFBMode, ''CTRMode]
        , a <- [''Int, ''String]
        ])

  context "when cookie has expired" $
    $(groupRoundTrip $ map (\(h, c, m, a) -> genPropRoundTrip h c m a 'modifyExpiration 'checkCookieExpired)
      [(h, c, m, a) |
          h <- [''SHA256, ''SHA384, ''SHA512]
        , c <- [''AES128, ''AES192, ''AES256]
        , m <- [''CBCMode, ''CFBMode, ''CTRMode]
        , a <- [''Int, ''String]
        ])
