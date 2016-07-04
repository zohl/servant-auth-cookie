{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE RankNTypes        #-}

import Test.HUnit
import Control.Monad
import Data.Time.Clock           (getCurrentTime, addUTCTime)
import System.IO
import System.Exit
import Control.Concurrent (threadDelay)
import Servant.Server.Experimental.Auth.Cookie.Internal
import Servant (Proxy(..))

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8

import Crypto.Random (drgNew)
import Crypto.Hash (HashAlgorithm, SHA512, SHA256)
import Crypto.Cipher.Types (BlockCipher, ctrCombine, cbcEncrypt, cbcDecrypt, cfbEncrypt, cfbDecrypt)
import Crypto.Cipher.AES (AES256, AES192, AES128)


tests :: [Test]
tests = [
    TestLabel "RandomSource" testRandomSource
  , TestLabel "ServerKey"    testServerKey
  , TestLabel "Cookie"       testCookie
  ]

main :: IO ()
main = do
  mapM_ (`hSetBuffering` LineBuffering) [stdout, stderr]

  Counts {cases, tried, errors, failures} <- runTestTT $ TestList tests
  when (cases /= tried || errors /= 0 || failures /= 0) $ exitFailure


testRandomSource :: Test
testRandomSource = TestList [
    TestCase $ do
      rs <- mkRandomSource drgNew 100
      s1 <- getRandomBytes rs 10
      s2 <- getRandomBytes rs 10
      assertBool "A source produced the same ouptut" (s1 /= s2)

  , TestCase $ do
      rs1 <- mkRandomSource drgNew 100
      rs2 <- mkRandomSource drgNew 100
      s1 <- getRandomBytes rs1 10
      s2 <- getRandomBytes rs2 10
      assertBool "Different sources produced the same ouptut" (s1 /= s2)

  , TestCase $ do
      rs <- mkRandomSource drgNew 10
      s1 <- getRandomBytes rs 10
      s2 <- getRandomBytes rs 10
      assertBool "Source after reset produced the same ouptut" (s1 /= s2)
  ]


testServerKey :: Test
testServerKey = TestList [
    TestCase $ do
      let keySize = 64
      sk <- mkServerKey keySize Nothing
      k <- getServerKey sk
      assertBool "A key has incorrect size" (BS.length k /= (keySize `div` 8))

  , TestCase $ do
      sk <- mkServerKey 16 (Just 1)

      -- TODO: This doesn't work in HUnit
      -- k1 <- getServerKey sk
      -- k2 <- threadDelay 2000000 >> getServerKey sk

      -- This (sometimes) works, but I don't know what kind of magic happens here
      getServerKey sk >>= (putStrLn . BS8.unpack)
      threadDelay 2000000 >> getServerKey sk >>= (putStrLn . BS8.unpack)

      k1 <- getServerKey sk
      k2 <- getServerKey sk

      assertBool "Expired key wasn't reset" (k1 /= k2)
  ]


testCookie :: Test
testCookie = TestList [
  TestLabel "ciphers" $ TestList [
      testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES256) cbcEncrypt cbcDecrypt 64
    , testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES256) cfbEncrypt cfbDecrypt 64
    , testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES256) ctrCombine ctrCombine 100

    , testCipher (Proxy :: Proxy SHA512) (Proxy :: Proxy AES256) ctrCombine ctrCombine 100
    , testCipher (Proxy :: Proxy SHA512) (Proxy :: Proxy AES192) ctrCombine ctrCombine 100
    , testCipher (Proxy :: Proxy SHA512) (Proxy :: Proxy AES128) ctrCombine ctrCombine 100
    ]
  ] where
      expFormat :: (String, Int)
      expFormat = expirationFormat defaultSettings

      mkCookie :: Int -> Int -> IO Cookie
      mkCookie dt size = do
        rs  <- mkRandomSource drgNew 1000

        iv'         <- getRandomBytes rs 16
        expiration' <- addUTCTime (fromIntegral dt) <$> getCurrentTime
        payload'    <- getRandomBytes rs size

        let cookie = Cookie {
            iv         = iv'
          , expiration = expiration'
          , payload    = payload'
          }

        return $ cookie


      cipherId :: forall h c. (HashAlgorithm h, BlockCipher c) =>
        Proxy h -> Proxy c -> CipherAlgorithm c -> CipherAlgorithm c -> Cookie
        -> IO (Either String Cookie)

      cipherId h _ encryptionAlgorithm decryptionAlgorithm cookie = do
        key <- mkServerKey 16 Nothing >>= getServerKey
        currentTime <- getCurrentTime

        let msg = encryptCookie
                    encryptionAlgorithm
                    h
                    key
                    cookie
                    (fst expFormat)

        return $ decryptCookie
                   decryptionAlgorithm
                   h
                   key
                   currentTime
                   expFormat
                   msg


      testCipher :: (HashAlgorithm h, BlockCipher c) =>
        Proxy h -> Proxy c -> CipherAlgorithm c -> CipherAlgorithm c -> Int -> Test

      testCipher h c encryptionAlgorithm decryptionAlgorithm size = TestCase $ do
        cookie <- mkCookie 10 size
        res <- cipherId h c encryptionAlgorithm decryptionAlgorithm cookie

        ($ res) $ either
          assertFailure
          (\cookie' -> assertEqual
                         "Decrypted message differs from the original one"
                         (payload cookie)
                         (payload cookie'))

