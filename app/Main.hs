{-# LANGUAGE MagicHash         #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Main where

import           Control.Monad.IO.Class    (liftIO)
import           Control.Monad.State       (StateT, execStateT)
import           Control.Monad.State.Class (get, put)
import           Data.Bits                 ((.|.))
import qualified Data.ByteString           as BS (null, ByteString, append, concat,
                                                  drop, length, take, takeWhile, intercalate)
import qualified Data.ByteString.Char8     as C (pack, putStrLn, unpack)
import qualified Data.ByteString.Lazy      as L (ByteString, foldrChunks,
                                                 readFile)
import qualified Data.ByteString.Lazy.Internal as L (ByteString(..))
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

sConsLazy :: BS.ByteString -> L.ByteString -> L.ByteString
sConsLazy b l =
    if BS.null b then
        l
    else
        L.Chunk b l

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

data Time = Time {
    t_hours        :: !Int
  , t_minutes      :: !Int
  , t_seconds      :: !Int
  , t_centiseconds :: !Int
} deriving (Eq, Ord, Show)

centiSecondsDiff :: Time -> Time -> Int
centiSecondsDiff a b =
    ((t_hours a - t_hours b) * 360000)
        + ((t_minutes a - t_minutes b) * 6000)
        + ((t_seconds a - t_seconds b) * 100)
        + (t_centiseconds a - t_centiseconds b)

-- also converts to JST (UTC+09:00)
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
      , t_minutes = read $ C.unpack $ dropTake 2 2 inp
      , t_seconds = read $ C.unpack $ dropTake 4 2 inp
      , t_centiseconds = read $ C.unpack $ dropTake 6 2 inp
    }

-- The returned list is in reverse order w.r.t. the input stream
parseNQtyPrice :: Int -> BS.ByteString -> [QtyPrice]
parseNQtyPrice = go []
    where
        go acc 0 _ = acc
        go acc n inp = go ((dropTake 5 7 inp, BS.take 5 inp):acc) (n - 1) (BS.drop 12 inp)

parseQuotePkt :: Time -> BS.ByteString -> QuotePkt
parseQuotePkt inPktTime rawPkt =
    QuotePkt {
        pktTime = inPktTime
      , acceptTime = parseAcceptTime $ dropTake 206 8 rawPkt
      , issueCode = dropTake 5 12 rawPkt
      , bids = parseNQtyPrice 5 $ BS.drop 29 rawPkt
      , asks = parseNQtyPrice 5 $ BS.drop 96 rawPkt
    }

type HeapEntry = Entry Time QuotePkt

usage :: IO ()
usage = putStrLn "usage: ./pcap-stock-quote [-r] <pcap-file>"

main :: IO ()
main = do
    args <- getArgs
    case args of
        ("-r":fn:[]) -> run True fn
        (fn:"-r":[]) -> run True fn
        (fn:[]) -> run False fn
        _ -> usage

run :: Bool -> String -> IO ()
run sort fn = do
    lbs <- L.readFile fn
    if sort then do
        s <- execStateT (parseAndPrintChunks lbs) (GetGlobalHeader, "")
        case s of
            (GetPacket h, _) ->
                foldMap (printQuotePkt . payload) h
            _ -> return ()
    else
        case runParser lbs pcapHdrParser of
            Left s -> putStrLn $ "pcapHdrParser failed: " ++ s
            Right (False, _) -> putStrLn "not a pcap file"
            Right (True, rest) ->
                parseNPrint rest

parseNPrint :: L.ByteString -> IO ()
parseNPrint L.Empty = return ()
parseNPrint i =
    case runParser i quotePktParser of
        Right (a, rest) ->
            case a of
                (Left _) -> parseNPrint rest
                (Right pkt) -> printQuotePkt pkt >> parseNPrint rest
        Left s -> putStrLn $ "quotePktParser failed: " ++ s

parseAndPrintChunks :: L.ByteString -> StateT (FoldState, BS.ByteString) IO ()
parseAndPrintChunks lbs =
    L.foldrChunks
        (\e a -> do
            (state, leftover) <- get
            put =<< liftIO (execStateT parseAndPrintChunk (state, leftover <> e))
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

type Parser a = BS.ByteString -> ParserOut a

data ParserOut a =
    NotEnoughInput
  | Done BS.ByteString a
  | Error String

(>*) :: Parser a -> (a -> Parser b) -> Parser b
(>*) f g i =
    case f i of
        NotEnoughInput -> NotEnoughInput
        Error s -> Error s
        Done leftover a -> g a leftover

runParser :: L.ByteString -> Parser a -> Either String (a, L.ByteString)
runParser l p = runParser' "" l p

runParser' :: BS.ByteString -> L.ByteString -> Parser a -> Either String (a, L.ByteString)
runParser' x L.Empty p =
    case p x of
        NotEnoughInput -> Left "NotEnoughInput"
        Done leftover a -> Right (a, L.Chunk leftover L.Empty)
        Error s -> Left s
runParser' x (L.Chunk y ys) p =
    case p (x <> y) of
        NotEnoughInput -> runParser' (x <> y) ys p
        Done leftover a -> Right (a, sConsLazy leftover ys)
        Error s -> Left s

pcapHdrParser :: Parser Bool
pcapHdrParser i =
    if BS.length i < pcapGlobalHdrLen then
        NotEnoughInput
    else
        let
            leftover = BS.drop pcapGlobalHdrLen i
        in
            if word32le i == pcapHdrMagic then
                Done leftover True
            else
                Done leftover False

quotePktParser :: Parser (Either Time QuotePkt)
quotePktParser i =
    if BS.length i < pcapPktHdrLen then
        NotEnoughInput
    else
        let
            pktTime = pcapTimeToTime (getWord32At 0 i, getWord32At 4 i)
            pktLen = fromIntegral $ getWord32At 8 i
            origLen = fromIntegral $ getWord32At 12 i
            leftover = BS.drop (pcapPktHdrLen + pktLen) i
        in
            if BS.length i < pcapPktHdrLen + pktLen then
                NotEnoughInput
            else
                if origLen /= pktLen || pktLen < quotePktLen then
                    Done leftover (Left pktTime)
                else
                    let
                        quotePktStart = BS.drop (pcapPktHdrLen + pktLen - quotePktLen) i
                    in
                        if BS.take 5 quotePktStart /= quotePktMagic then
                            Done leftover (Left pktTime)
                        else
                            Done leftover (Right $ parseQuotePkt pktTime quotePktStart)

parseAndPrintChunk :: StateT (FoldState, BS.ByteString) IO ()
parseAndPrintChunk = do
    (state, chunk) <- get
    case state of
        GetGlobalHeader ->
            if BS.length chunk < pcapGlobalHdrLen then
                return ()
            else
                if getWord32At 0 chunk == pcapHdrMagic then do
                    put (GetPacket Heap.empty, BS.drop pcapGlobalHdrLen chunk)
                    parseAndPrintChunk
                else do
                    put (FailState "Not a pcap file", "")
                    return ()
        GetPacket h -> do
            if BS.length chunk < pcapPktHdrLen then
                return ()
            else do
                let pktTime = pcapTimeToTime (getWord32At 0 chunk, getWord32At 4 chunk)
                    pktLen = fromIntegral $ getWord32At 8 chunk
                    origLen = fromIntegral $ getWord32At 12 chunk
                    goNextPkt h' = do
                        put (GetPacket h', BS.drop (pcapPktHdrLen + pktLen) chunk)
                        parseAndPrintChunk
                if BS.length chunk < pcapPktHdrLen + pktLen then
                    return ()
                else
                    if origLen /= pktLen || pktLen < quotePktLen then do
                        h' <- liftIO $ flushHeap pktTime h
                        goNextPkt h'
                    else do
                        let quotePktStart = BS.drop (pcapPktHdrLen + pktLen - quotePktLen) chunk
                        if BS.take 5 quotePktStart /= quotePktMagic then do
                            h' <- liftIO $ flushHeap pktTime h
                            goNextPkt h'
                        else do
                            h' <- liftIO $ flushHeap pktTime h
                            let quotePkt = parseQuotePkt pktTime (BS.take quotePktLen quotePktStart)
                            goNextPkt
                                (Heap.insert
                                    (Entry (acceptTime quotePkt) quotePkt)
                                    h')
        FailState msg -> do
            put (FailState msg, "")
            return ()

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

printQuotePkt :: QuotePkt -> IO ()
printQuotePkt QuotePkt{..} =
    C.putStrLn $ timeS pktTime <> " " <> timeS acceptTime <> " " <> issueCode <> " "
        <> BS.concat (map (\(q, p) -> q <> "@" <> p <> " ") bids)
        <> BS.intercalate " " (map (\(q, p) -> q <> "@" <> p) $ reverse asks)
    where
        timeS t = C.pack $ padShow (t_hours t) ++ ":"
                    ++ padShow (t_minutes t) ++ ":"
                    ++ padShow (t_seconds t) ++ "."
                    ++ padShow (t_centiseconds t)
        padShow x = if x < 10 then '0':show x else show x
        qtyPriceStr (q, p) = q <> "@" <> p
        -- removeLeadingZeros, unused
        rlz a = let nlz = BS.length (BS.takeWhile (== 0x30) a)
                in if nlz == BS.length a then "0" else BS.drop nlz a
