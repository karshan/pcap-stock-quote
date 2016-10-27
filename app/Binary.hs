{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PartialTypeSignatures #-}

module Binary where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.State.Class (get, put)
import Control.Monad.State.Strict (StateT, evalStateT)
import Data.Binary.Get
       (Decoder(..), Get, getByteString, getWord32le, pushChunk,
        runGetIncremental, runGetOrFail, skip)
import Data.Bits ((.|.))
import qualified Data.ByteString as BS
       (ByteString, append, drop, length, take)
import qualified Data.ByteString.Char8 as C (putStrLn)
import qualified Data.ByteString.Lazy as L
       (ByteString, foldrChunks, readFile)
import qualified Data.ByteString.Unsafe as BS (unsafeIndex)
import GHC.Base (Int(..), uncheckedShiftL#)
import GHC.Word (Word32(..))
import QuoteParser (QuotePkt(..), printQuotePkt, parseQuotePkt)
import System.Environment (getArgs)
import Time

shiftl_w32 (W32# w) (I# i) = W32# (w `uncheckedShiftL#` i)

word32le :: BS.ByteString -> Word32
word32le =
  \s ->
    (fromIntegral (s `BS.unsafeIndex` 3) `shiftl_w32` 24) .|.
    (fromIntegral (s `BS.unsafeIndex` 2) `shiftl_w32` 16) .|.
    (fromIntegral (s `BS.unsafeIndex` 1) `shiftl_w32` 8) .|.
    (fromIntegral (s `BS.unsafeIndex` 0))

run :: Bool -> L.ByteString -> IO ()
run sort lbs = do
  case runGetOrFail getGlobalHeader lbs of
    Right (leftover, _, True) ->
      evalStateT (parseAndPrintChunks leftover) (runGetIncremental getPacket)
    _ -> putStrLn "Not a pcap file"

parseAndPrintChunks :: L.ByteString -> StateT (Decoder ETQ) IO ()
parseAndPrintChunks lbs =
  L.foldrChunks
    (\e a -> do
       d <- get
       put =<< liftIO (parseAndPrintChunk (d `pushChunk` e))
       a)
    (return ())
    lbs

quotePktLen :: Int
quotePktLen = 215

parseAndPrintChunk :: Decoder ETQ -> IO (Decoder ETQ)
parseAndPrintChunk d =
  case d of
    Done leftover _ (Right quotePkt) -> do
      liftIO $ printQuotePkt quotePkt
      parseAndPrintChunk (runGetIncremental getPacket `pushChunk` leftover)
    Done leftover _ (Left tm) -> do
      parseAndPrintChunk (runGetIncremental getPacket `pushChunk` leftover)
    resultDecoder -> return resultDecoder

getGlobalHeader :: Get Bool
getGlobalHeader = do
  magic <- getWord32le
  skip 20
  return $ magic == 0xa1b2c3d4

type ETQ = Either Time QuotePkt

getPacket :: Get (Either Time QuotePkt)
getPacket = do
  tm <- curry pcapTimeToTime <$> getWord32le <*> getWord32le
  pktlen <- fromIntegral <$> getWord32le
  origlen <- fromIntegral <$> getWord32le
  if origlen /= pktlen || pktlen < quotePktLen
    then do
      skip pktlen
      return (Left tm)
    else do
      skip (pktlen - quotePktLen)
      magic <- getByteString 5
      if magic == "B6034"
        then Right . parseQuotePkt tm . BS.append "B6034" <$>
             getByteString (quotePktLen - 5)
        else do
          skip (quotePktLen - 5)
          return $ Left tm
