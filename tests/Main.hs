{-# LANGUAGE OverloadedStrings #-}

import Test.HUnit
import Control.Monad
import System.IO
import System.Exit
import Control.Concurrent (threadDelay)
import Servant.Server.Experimental.Auth.Cookie.Internal
import Control.DeepSeq

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Crypto.Random (drgNew)


tests :: [Test]
tests = [
    TestLabel "RandomSource" testRandomSource
  , TestLabel "ServerKey"    testServerKey
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

      -- This works, but I don't know what kind of magic happens here
      getServerKey sk >>= (putStrLn . BS8.unpack)
      threadDelay 2000000 >> getServerKey sk >>= (putStrLn . BS8.unpack)

      k1 <- getServerKey sk
      k2 <- getServerKey sk

      assertBool "Expired key wasn't reset" (k1 /= k2)
  ]
