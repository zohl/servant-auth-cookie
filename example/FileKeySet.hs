{-# LANGUAGE CPP                   #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}
{-# LANGUAGE OverloadedLists       #-}
{-# LANGUAGE TupleSections         #-}

module FileKeySet (
  FileKSParams (..)
, mkFileKey
, mkFileKeySet
) where

import Prelude ()
import Prelude.Compat
import Control.Monad.Catch (MonadThrow)
import Control.Monad (when)
import Control.Concurrent (threadDelay)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Time.Clock (UTCTime(..), getCurrentTime)
import Data.Time (formatTime, defaultTimeLocale)
import Data.List (sort)
import Servant.Server.Experimental.Auth.Cookie
import System.Directory (doesFileExist, getModificationTime, createDirectoryIfMissing, listDirectory, removeFile)
import System.FilePath.Posix ((</>), (<.>))
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Char8 as BSC8

----------------------------------------------------------------------------
-- KeySet
-- A custom implementation of a keyset on top of 'RenewableKeySet'.
-- Keys are stored as files with base64 encoded data in 'test-key-set' directory.
-- To add a key just throw a file into the directory.
-- To remove a key delete corresponding file in the directory.
-- Both operations can be performed via web interface (see '/keys' page).


data FileKSParams = FileKSParams
  { fkspPath    :: FilePath
  , fkspMaxKeys :: Int
  , fkspKeySize :: Int
  }

data FileKSState = FileKSState
  { fkssLastModified :: UTCTime } deriving Eq


mkFileKey :: FileKSParams -> IO ()
mkFileKey FileKSParams {..} = (,) <$> mkName <*> mkKey >>= uncurry writeFile where

  mkKey = generateRandomBytes fkspKeySize
    >>= return
      . BSC8.unpack
      . Base64.encode

  mkName = getCurrentTime
    >>= return
      . (fkspPath </>)
      . (<.> "b64")
      . formatTime defaultTimeLocale "%0Y%m%d%H%M%S"
    >>= \name -> do
      exists <- doesFileExist name
      if exists
      then (threadDelay 1000000) >> mkName
        -- ^ we don't want to change the keys that often
      else return name


mkFileKeySet :: (MonadIO m, MonadThrow m)
  => FileKSParams
  -> m (RenewableKeySet FileKSState FileKSParams)
mkFileKeySet = mkKeySet where

  mkKeySet FileKSParams {..} = do
    liftIO $ do
      createDirectoryIfMissing True fkspPath
      listDirectory fkspPath >>= \fs -> when (null fs) $
        mkFileKey FileKSParams {..}

    let fkssLastModified = UTCTime (toEnum 0) 0

    mkRenewableKeySet
      RenewableKeySetHooks {..}
      FileKSParams {..}
      FileKSState {..}

  rkshNeedUpdate FileKSParams {..} (_, FileKSState {..}) = do
    lastModified <- liftIO $ getModificationTime fkspPath
    return (lastModified > fkssLastModified)

  getLastModifiedFiles FileKSParams {..} = listDirectory fkspPath
    >>= return . map (fkspPath </>)
    >>= \fs -> zip <$> (mapM getModificationTime fs) <*> (return fs)
    >>= return
      . map snd
      . take fkspMaxKeys
      . reverse
      . sort

  readKey = fmap (either (error "wrong key format") id . Base64.decode . BSC8.pack) . readFile

  rkshNewState FileKSParams {..} (_, s) = liftIO $ do
    lastModified <- getModificationTime fkspPath
    keys <- getLastModifiedFiles FileKSParams {..} >>= mapM readKey
    return (keys, s {fkssLastModified = lastModified})

  rkshRemoveKey FileKSParams {..} key = liftIO $ getLastModifiedFiles FileKSParams {..}
    >>= \fs -> zip fs <$> mapM readKey fs
    >>= return . filter ((== key) . snd)
    >>= mapM_ (removeFile . fst)
