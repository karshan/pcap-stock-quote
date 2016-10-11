{-# LANGUAGE MagicHash         #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Main where

import           Control.Monad.IO.Class    (liftIO)
import           Control.Monad.State       (StateT, execStateT)
import           Control.Monad.State.Class (get, put)
import           Data.Bits                 ((.|.))
import qualified Data.ByteString           as BS (ByteString, append, concat,
                                                  drop, length, take)
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

shiftl_w32 (W32# w) (I# i) = W32# (w `uncheckedShiftL#`   i)

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

data FoldState =
    GetGlobalHeader
  | GetPacket (Heap HeapEntry)
  | FailState String
        deriving (Eq, Show)

data Time = Time {
    t_hours        :: !Int
  , t_minutes      :: !Int
  , t_seconds      :: !Int
  , t_centiseconds :: !Int
} deriving (Eq, Ord, Show)

centiSecondsDiff :: Time -> Time -> Int
centiSecondsDiff a b = ((t_hours a - t_hours b) * 360000) + ((t_minutes a - t_minutes b) * 6000) + ((t_seconds a - t_seconds b) * 100) + ((t_centiseconds a - t_centiseconds b))

pcapTimeToTime :: (Word32, Word32) -> Time
pcapTimeToTime (pktSec, pktUsec) =
    let (_, _, _, hours, minutes, seconds) = toGregorian $ addUTCTime (9 * 3600) $ posixSecondsToUTCTime $ fromIntegral pktSec
    in Time hours minutes seconds ((fromIntegral pktUsec) `div` 10000)

type QtyPrice = (BS.ByteString, BS.ByteString)

data QuotePkt = QuotePkt {
    pktTime    :: !Time
  , acceptTime :: !Time
  , issueCode  :: !BS.ByteString
  , bids       :: [QtyPrice] -- TODO Vec ?
  , asks       :: [QtyPrice]
} deriving (Eq, Show)

parseAcceptTime :: BS.ByteString -> Time
parseAcceptTime inp =
    Time {
        t_hours = read $ C.unpack $ BS.take 2 inp
      , t_minutes = read $ C.unpack $ BS.take 2 $ BS.drop 2 inp
      , t_seconds = read $ C.unpack $ BS.take 2 $ BS.drop 4 inp
      , t_centiseconds = read $ C.unpack $ BS.take 2 $ BS.drop 6 inp
    }

getQtyPrice :: Int -> [QtyPrice] -> BS.ByteString -> [QtyPrice]
getQtyPrice 0 acc _ = acc
getQtyPrice n acc inp = getQtyPrice (n - 1) ((BS.take 7 $ BS.drop 5 inp, BS.take 5 inp):acc) (BS.drop 12 inp)

parseQuotePkt :: Time -> BS.ByteString -> QuotePkt
parseQuotePkt inPktTime rawPkt =
    QuotePkt {
        pktTime = inPktTime
      , acceptTime = parseAcceptTime $ BS.take 8 $ BS.drop 206 rawPkt
      , issueCode = BS.take 12 $ BS.drop 5 rawPkt
      , bids = getQtyPrice 5 [] $ BS.drop 29 rawPkt
      , asks = getQtyPrice 5 [] $ BS.drop 96 rawPkt
    }

type HeapEntry = Entry Time QuotePkt

main :: IO ()
main = do
    (fn:_) <- getArgs
    lbs <- L.readFile fn
    s <- execStateT (parseAndPrintChunks lbs) (GetGlobalHeader, "")
    case s of
        (GetPacket h, _) ->
            flushHeap' h
        _ -> return ()

parseAndPrintChunks :: L.ByteString -> StateT (FoldState, BS.ByteString) IO ()
parseAndPrintChunks lbs =
    L.foldrChunks
        (\e a -> do
            (state, leftover) <- get
            put =<< liftIO (parseAndPrintChunk (leftover `BS.append` e) state)
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

parseAndPrintChunk :: BS.ByteString -> FoldState -> IO (FoldState, BS.ByteString)
parseAndPrintChunk chunk state =
    case state of
        GetGlobalHeader ->
            if BS.length chunk < pcapGlobalHdrLen then
                return (GetGlobalHeader, chunk)
            else
                if getWord32At 0 chunk == pcapHdrMagic then
                    parseAndPrintChunk (BS.drop pcapGlobalHdrLen chunk) (GetPacket Heap.empty)
                else
                    return (FailState "Not a pcap file", "")
        GetPacket h -> do
            if BS.length chunk < pcapPktHdrLen then
                return (GetPacket h, chunk)
            else do
                let pktTime = pcapTimeToTime (getWord32At 0 chunk, getWord32At 4 chunk)
                    pktLen = fromIntegral $ getWord32At 8 chunk
                    origLen = fromIntegral $ getWord32At 12 chunk
                    goNextPkt h' = parseAndPrintChunk (BS.drop (pcapPktHdrLen + pktLen) chunk) (GetPacket h')
                if BS.length chunk < pcapPktHdrLen + pktLen then
                    return (GetPacket h, chunk)
                else
                    if origLen /= pktLen || pktLen < quotePktLen then do
                        h' <- flushHeap pktTime h
                        goNextPkt h'
                    else do
                        let quotePktStart = BS.drop (pcapPktHdrLen + pktLen - quotePktLen) chunk
                        if BS.take 5 quotePktStart /= quotePktMagic then do
                            h' <- flushHeap pktTime h
                            goNextPkt h'
                        else do
                            h' <- flushHeap pktTime h
                            let quotePkt = parseQuotePkt pktTime (BS.take quotePktLen quotePktStart)
                            goNextPkt
                                (Heap.insert
                                    (Entry (acceptTime quotePkt) quotePkt)
                                    h')
        FailState msg -> return (FailState msg, "")

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

flushHeap' :: Heap HeapEntry -> IO ()
flushHeap' h =
    case Heap.uncons h of
        Just (min, rest) -> do
            printQuotePkt (payload min)
            flushHeap' rest
        _ -> return ()


printQuotePkt :: QuotePkt -> IO ()
printQuotePkt QuotePkt{..} =
    C.putStrLn $ timeS pktTime <> " " <> timeS acceptTime <> " " <> issueCode <> " "
        <> BS.concat (map (\(q, p) -> q <> "@" <> p <> " ") bids)
        <> BS.concat (map (\(q, p) -> q <> "@" <> p <> " ") $ reverse asks)
    where
        timeS t = C.pack $ padShow (t_hours t) ++ ":" ++ padShow (t_minutes t) ++ ":" ++ padShow (t_seconds t) ++ "." ++ decPadShow (t_centiseconds t)
        padShow x = if x < 10 then '0':show x else show x
        decPadShow x = if x < 10 then show x ++ "0" else show x
