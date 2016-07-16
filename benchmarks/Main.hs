{-# LANGUAGE ExistentialQuantification #-}

import Servant.Server.Experimental.Auth.Cookie.Internal

import Crypto.Random (drgNew, DRG, getSystemDRG)
import Data.ByteString (ByteString)
import Control.Monad (when)

import Criterion (Benchmark, bench, nfIO)
import Criterion.Main (bgroup, defaultMain)


data DRGInit = forall d. (DRG d) => MkDRGInit (IO d)
mkDRGInit :: (DRG d) => IO d -> DRGInit
mkDRGInit = MkDRGInit


benchRandomSource :: [Benchmark]
benchRandomSource = [ mkBenchmark name drg size | (name, drg) <- drgs, size <- sizes] where

  sizes :: [Int]
  sizes = [
      2000
    -- , 4000
    -- , 8000
    ]

  drgs :: [(String, DRGInit)]
  drgs = [
      ("ChaCha", mkDRGInit drgNew)
    -- , ("System", mkDRGInit getSystemDRG)
    ]

  mkBenchmark :: String -> DRGInit -> Int -> Benchmark
  mkBenchmark name (MkDRGInit drg) size = bench
    (name ++ "_" ++ (show size))
    (nfIO $ mkRandomSource drg size >>= drainRandomSource 16 1000)

  drainRandomSource :: (DRG d) => Int -> Int -> RandomSource d -> IO ()
  drainRandomSource chunkSize iterNum rs = step iterNum Nothing where
    step :: Int -> Maybe ByteString -> IO ()
    step 0 _  = return ()
    step n ms = do
      s' <- getRandomBytes rs chunkSize
      when (maybe False id $ ((== s') <$> ms)) $ error "RandomSource produced the same output"
      step (n-1) (Just s')


main :: IO ()
main = defaultMain [
    bgroup "RandomSource" benchRandomSource
  ]


