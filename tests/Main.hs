{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE RecordWildCards   #-}

import Test.HUnit
import Control.Monad
import Data.Time.Clock           (getCurrentTime, addUTCTime)
import Data.Serialize (Serialize)
import GHC.Generics (Generic)
import System.IO
import System.Exit
import Control.Concurrent (threadDelay)
import Servant.Server.Experimental.Auth.Cookie.Internal
import Servant (Proxy(..))

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8

import Crypto.Random (drgNew)
import Crypto.Hash (HashAlgorithm, SHA512, SHA384, SHA256)
import Crypto.Cipher.Types (BlockCipher, ctrCombine, cbcEncrypt, cbcDecrypt, cfbEncrypt, cfbDecrypt)
import Crypto.Cipher.AES (AES256, AES192, AES128)


tests :: [Test]
tests = [
    TestLabel "RandomSource" testRandomSource
  , TestLabel "ServerKey"    testServerKey
  , TestLabel "Cookie"       testCookie
  , TestLabel "Session"      testSession
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
      TestLabel "different algorithms" $ TestList [
          testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES256) cbcEncrypt cbcDecrypt 64
        , testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES256) cfbEncrypt cfbDecrypt 64
        , testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES256) ctrCombine ctrCombine 100
        ]
    , TestLabel "different ciphers" $ TestList [
          testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES256) ctrCombine ctrCombine 100
        , testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES192) ctrCombine ctrCombine 100
        , testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES128) ctrCombine ctrCombine 100
        ]
    , TestLabel "different hashes" $ TestList [
          testCipher (Proxy :: Proxy SHA512) (Proxy :: Proxy AES256) ctrCombine ctrCombine 100
        , testCipher (Proxy :: Proxy SHA384) (Proxy :: Proxy AES256) ctrCombine ctrCombine 100
        , testCipher (Proxy :: Proxy SHA256) (Proxy :: Proxy AES256) ctrCombine ctrCombine 100
        ]
    , TestLabel "bad cases" $ TestList [
          testCustomCookie
            (mkCookie 10 100)
            (return . BS8.drop 1)
            (either (== errBadMAC) (const False))

        , testCustomCookie
            (mkCookie 0 100)
            (return)
            (either (== errExpired) (const False))
        ]
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
        Proxy h -> Proxy c -> CipherAlgorithm c -> CipherAlgorithm c
        -> IO Cookie
        -> (BS8.ByteString -> IO BS8.ByteString)
        -> IO (Either String Cookie)

      cipherId h _ encryptAlgo decryptAlgo mkCookie' encryptionHook = do

          cookie'     <- mkCookie'
          key         <- mkServerKey 16 Nothing >>= getServerKey
          currentTime <- getCurrentTime
          msg         <- encryptionHook $ encryptCookie
                           encryptAlgo
                           h
                           key
                           cookie'
                           (fst expFormat)

          return $ decryptCookie
                     decryptAlgo
                     h
                     key
                     currentTime
                     expFormat
                     msg


      testCipher :: (HashAlgorithm h, BlockCipher c) =>
        Proxy h -> Proxy c -> CipherAlgorithm c -> CipherAlgorithm c -> Int -> Test

      testCipher h c encryptionAlgorithm decryptionAlgorithm size = TestCase $ do
        cookie <- mkCookie 10 size
        res <- cipherId h c encryptionAlgorithm decryptionAlgorithm (return cookie) return

        ($ res) $ either
          assertFailure
          (\cookie' -> assertEqual
                         "Decrypted message differs from the original one"
                         (payload cookie)
                         (payload cookie'))


      testCustomCookie :: IO Cookie -> (BS8.ByteString -> IO BS8.ByteString) ->
        (Either String Cookie -> Bool) -> Test

      testCustomCookie mkCookie' encryptionHook check = TestCase $ do
        res <- cipherId
          (Proxy :: Proxy SHA256)
          (Proxy :: Proxy AES256)
          ctrCombine ctrCombine
          mkCookie' encryptionHook

        assertBool "Unexpected result of cookie decryption" (check res)


data Tree a = Leaf a
            | Node a [Tree a]
  deriving (Eq, Generic)
instance (Serialize a) => Serialize (Tree a)


testData1 :: Tree Int
testData1 = Node 0 [
    Node 1 [Leaf 3, Leaf 4]
  , Node 2 [Leaf 5, Leaf 6]
  ]

testData2 :: Tree String
testData2 = Node "" [
    Node "b" [
        Leaf "ar"
      , Leaf "az"
      ]
  , Leaf "corge"
  , Node "g" [
      Leaf "arply"
    , Leaf "rault"
    ]
  , Leaf "foo"
  , Node "qu" [
        Leaf "x"
      , Leaf "ux"
      ]
  ]


testSession :: Test
testSession = TestList $ [
    testCustomSession defaultSettings testData1
  , testCustomSession defaultSettings testData2

  , testCustomSession (($ defaultSettings) $ \(Settings {..}) -> Settings {
        encryptAlgorithm = cbcEncrypt
      , decryptAlgorithm = cbcDecrypt
      , ..
      }) testData1

  , testCustomSession (($ defaultSettings) $ \(Settings {..}) -> Settings {
        encryptAlgorithm = cbcEncrypt
      , decryptAlgorithm = cbcDecrypt
      , ..
      }) testData2

  , testCustomSession (($ defaultSettings) $ \(Settings {..}) -> Settings {
        encryptAlgorithm = cfbEncrypt
      , decryptAlgorithm = cfbDecrypt
      , ..
      }) testData1

  , testCustomSession (($ defaultSettings) $ \(Settings {..}) -> Settings {
        encryptAlgorithm = cfbEncrypt
      , decryptAlgorithm = cfbDecrypt
      , ..
      }) testData2

  ] where
      sessionId :: forall a. (Serialize a) => Settings -> a -> IO (Either String a)
      sessionId settings session = do
        rs <- mkRandomSource drgNew 100
        sk <- mkServerKey 16 Nothing
        let settings' = ($ settings) $ \(Settings {..}) -> Settings {
            randomSource = rs
          , serverKey = sk
          , ..
          }
        encryptSession settings' session >>= decryptSession settings'

      testCustomSession :: forall a. (Eq a, Serialize a) => Settings -> a -> Test
      testCustomSession settings session = TestCase $ do
        result <- either (const False) (\session' -> session == session')
              <$> sessionId settings session
        assertBool "Unexpected result of session decryption" result

