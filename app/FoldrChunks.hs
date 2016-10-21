{-# LANGUAGE MagicHash         #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module FoldrChunks where

import           Control.Monad.IO.Class    (liftIO)
import           Control.Monad.State       (StateT, execStateT)
import           Control.Monad.State.Class (get, put)
import           Data.Bits                 ((.|.))
import qualified Data.ByteString           as BS (ByteString, append, concat,
                                                  drop, length, take, takeWhile, intercalate)
import qualified Data.ByteString.Char8     as C (pack, putStrLn, unpack)
import qualified Data.ByteString.Lazy      as L (ByteString, foldrChunks,
                                                 readFile)
import qualified Data.ByteString.Unsafe    as BS (unsafeIndex)
import           Data.DateTime             (toGregorian)
import           Data.Heap                 (Entry (..), Heap)
import qualified Data.Heap                 as Heap
import           Data.Monoid               ((<>))
import           Data.Time.Clock
import           Data.Time.Clock.POSIX
import           GHC.Base                  (Int (..), uncheckedShiftL#)
import           GHC.Word                  (Word32 (..))
import           System.Environment        (getArgs)
import Time (Time (..), pcapTimeToTime, centiSecondsDiff)
import QuoteParser (printQuotePkt, QuotePkt (..), parseQuotePkt)

-- shiftl_w32 and word32le are from the binary package
-- https://hackage.haskell.org/package/binary-strict-0.2/src/src/Data/Binary/Strict/Get.hs
shiftl_w32 :: Word32 -> Int -> Word32
shiftl_w32 (W32# w) (I# i) = W32# (w `uncheckedShiftL#`   i)

-- Read the first 4 bytes of a ByteString as a Word32
word32le :: BS.ByteString -> Word32
{-# INLINE word32le #-}
word32le = \s ->
              (fromIntegral (s `BS.unsafeIndex` 3) `shiftl_w32` 24) .|.
              (fromIntegral (s `BS.unsafeIndex` 2) `shiftl_w32` 16) .|.
              (fromIntegral (s `BS.unsafeIndex` 1) `shiftl_w32`  8) .|.
              (fromIntegral (s `BS.unsafeIndex` 0) )

getWord32At :: Int -> BS.ByteString -> Word32
{-# INLINE getWord32At #-}
getWord32At n = word32le . BS.drop n

dropTake :: Int -> Int -> BS.ByteString -> BS.ByteString
dropTake d t = BS.take t . BS.drop d

data FoldState =
    GetGlobalHeader
  | GetPacket (Heap HeapEntry)
  | FailState String
        deriving (Eq, Show)

type HeapEntry = Entry Time QuotePkt

run :: Bool -> String -> IO ()
run sort fn = do
    lbs <- L.readFile fn
    s <- execStateT (parseAndPrintChunks sort lbs) (GetGlobalHeader, "")
    case s of
        (GetPacket h, _) ->
            foldMap (printQuotePkt . payload) h
        _ -> return ()

parseAndPrintChunks :: Bool -> L.ByteString -> StateT (FoldState, BS.ByteString) IO ()
parseAndPrintChunks sort lbs =
    L.foldrChunks
        (\e a -> do
            (state, leftover) <- get
            put =<< liftIO (parseAndPrintChunk sort (leftover `BS.append` e) state)
            a)
        (return ())
        lbs

quotePktLen, pcapPktHdrLen :: Int
pcapGlobalHdrLen = 24
pcapPktHdrLen = 16
quotePktLen = 215

pcapHdrMagic :: Word32
pcapHdrMagic = 0xa1b2c3d4

quotePktMagic :: BS.ByteString
quotePktMagic = "B6034"

parseAndPrintChunk :: Bool -> BS.ByteString -> FoldState -> IO (FoldState, BS.ByteString)
parseAndPrintChunk sort chunk state =
    case state of
        GetGlobalHeader ->
            if BS.length chunk < pcapGlobalHdrLen then
                return (GetGlobalHeader, chunk)
            else
                if getWord32At 0 chunk == pcapHdrMagic then
                    parseAndPrintChunk sort (BS.drop pcapGlobalHdrLen chunk) (GetPacket Heap.empty)
                else
                    return (FailState "Not a pcap file", "")
        GetPacket h -> do
            if BS.length chunk < pcapPktHdrLen then
                return (GetPacket h, chunk)
            else do
                let pktTime = pcapTimeToTime (getWord32At 0 chunk, getWord32At 4 chunk)
                    pktLen = fromIntegral $ getWord32At 8 chunk
                    origLen = fromIntegral $ getWord32At 12 chunk
                    goNextPkt h' = parseAndPrintChunk sort (BS.drop (pcapPktHdrLen + pktLen) chunk) (GetPacket h')
                if BS.length chunk < pcapPktHdrLen + pktLen then
                    return (GetPacket h, chunk)
                else
                    if origLen /= pktLen || pktLen < quotePktLen then do
                        if sort then do
                            h' <- flushHeap pktTime h
                            goNextPkt h'
                        else
                            goNextPkt h
                    else do
                        let quotePktStart = BS.drop (pcapPktHdrLen + pktLen - quotePktLen) chunk
                        if BS.take 5 quotePktStart /= quotePktMagic then do
                            if sort then do
                                h' <- flushHeap pktTime h
                                goNextPkt h'
                            else
                                goNextPkt h
                        else do
                            let quotePkt = parseQuotePkt pktTime (BS.take quotePktLen quotePktStart)
                            if sort then do
                                h' <- flushHeap pktTime h
                                goNextPkt
                                    (Heap.insert
                                        (Entry (acceptTime quotePkt) quotePkt)
                                        h')
                            else do
                                printQuotePkt quotePkt
                                goNextPkt h
        FailState msg -> return (FailState msg, "")

-- Print all packets in the heap that have accept times more than 3 seconds in the past
-- from the given time.
flushHeap :: Time -> Heap HeapEntry -> IO (Heap HeapEntry)
flushHeap t h =
    case Heap.uncons h of
        Just (min, rest) ->
            if t `centiSecondsDiff` priority min > 300 then do
                printQuotePkt (payload min)
                flushHeap t rest
            else
                return h
        _ -> return h
