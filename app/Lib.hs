{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Lib where

import           Control.Monad.IO.Class        (MonadIO, liftIO)
import           Control.Monad.Random          (evalRandT)
import           Control.Monad.Random.Class    (MonadRandom, getRandomR)
import           Criterion.Main                (bench, defaultMain, nfIO)
import qualified Data.ByteString               as BS (ByteString, appendFile,
                                                      concat, drop, head,
                                                      intercalate, last,
                                                      replicate, take,
                                                      writeFile)
import qualified Data.ByteString.Char8         as C (pack, putStrLn)
import qualified Data.ByteString.Lazy          as L (ByteString, readFile)
import qualified Data.ByteString.Lazy.Internal as L (ByteString (..))
import           Data.Heap                     (Entry (..), Heap)
import qualified Data.Heap                     as Heap
import           Data.Monoid                   ((<>))
import           GHC.Word                      (Word32 (..))
import           Parser                        (Parser (..), bytes, runParser,
                                                skip, word32)
import           System.Environment            (getArgs)
import           System.Random                 (getStdGen)
import           Time                          (Time (..), addCentiSeconds,
                                                centiSecondsDiff,
                                                pcapTimeToTime, timeToPcapTime)
import           Util                          (dropTake, putWord32le)

usage :: IO ()
usage = putStrLn "usage: ./pcap-stock-quote [-r] <pcap-file>"

benchMain :: IO ()
benchMain =
    defaultMain [ bench "mdf-kospi200.20110216-0.pcap-normal" $ nfIO (run False "mdf-kospi200.20110216-0.pcap")
                , bench "mdf-kospi200.20110216-0.pcap-sort" $ nfIO (run True "mdf-kospi200.20110216-0.pcap")
                ]
main :: IO ()
main = do
    args <- getArgs
    case args of
        ("-g":n:[]) -> getStdGen >>= evalRandT (gen (read n))
        ("-r":fn:[]) -> run True fn
        (fn:"-r":[]) -> run True fn
        (fn:[]) -> run False fn
        _ -> usage

run :: Bool -> String -> IO ()
run sort fn = do
    lbs <- L.readFile fn
    case runParser lbs pcapHdrParser of
        Left s -> putStrLn $ "pcapHdrParser failed: " ++ s
        Right (False, _) -> putStrLn "Error: not a pcap file"
        Right (True, rest) ->
            if sort then
                runSort rest
            else
                runNormal rest

type HeapEntry = Entry Time QuotePkt

runSort :: L.ByteString -> IO ()
runSort inp = go Heap.empty inp
    where
        go :: Heap HeapEntry -> L.ByteString -> IO ()
        go h L.Empty = foldMap (printQuotePkt . payload) h
        go h i =
            case runParser i quotePktParser of
                Right (a, rest) ->
                    case a of
                        (Left time) -> do
                            h' <- flushHeap time h
                            go h' rest
                        (Right pkt) -> do
                            h' <- flushHeap (pktTime pkt) h
                            go (Heap.insert (Entry (acceptTime pkt) pkt) h') rest
                Left s -> putStrLn $ "quotePktParser failed: " ++ s

-- Print all packets in the heap that have accept times more than 3 seconds in the past
-- from the given time.
flushHeap :: Time -> Heap HeapEntry -> IO (Heap HeapEntry)
flushHeap t h =
    case Heap.uncons h of
        Just (minE, rest) ->
            if t `centiSecondsDiff` priority minE > 300 then do
                printQuotePkt (payload minE)
                flushHeap t rest
            else
                return h
        _ -> return h

runNormal :: L.ByteString -> IO ()
runNormal L.Empty = return ()
runNormal i =
    case runParser i quotePktParser of
        Right (a, rest) ->
            case a of
                (Left _) -> runNormal rest
                (Right pkt) -> printQuotePkt pkt >> runNormal rest
        Left s -> putStrLn $ "quotePktParser failed: " ++ s

gen :: (MonadIO m, MonadRandom m) => Integer -> m ()
gen n' = do
    liftIO $ BS.writeFile "gen.pcap" ((w32 pcapHdrMagic) <> BS.replicate 20 0)
    go (Time 0 0 3 0) n'
    where
        go _ 0 = return ()
        go t n = do
            let pktHdr l = ((\(s, us) -> w32 s <> w32 us) $ timeToPcapTime t)
                        <> w32 (fromIntegral l) <> w32 (fromIntegral l)
            nextT <- (t `addCentiSeconds`) <$> getRandomR (0, maxPacketTimeDiff)
            isQuotePkt <- p pQuote
            if isQuotePkt then do
                pktLen :: Int <- getRandomR (quotePktLen, maxPacketLen)
                acceptT <- (t `addCentiSeconds`) <$> getRandomR (-299, 299)
                let pkt = pktHdr pktLen
                        <> BS.replicate (fromIntegral $ pktLen - quotePktLen) 0
                        <> quotePktMagic <> BS.replicate 201 0
                        <> timeS acceptT <> "\255"
                liftIO $ BS.appendFile "gen.pcap" pkt
                go nextT (n - 1)
            else do
                pktLen :: Int <- getRandomR (0, maxPacketLen)
                let pkt = pktHdr pktLen
                        <> BS.replicate (fromIntegral pktLen) 0
                liftIO $ BS.appendFile "gen.pcap" pkt
                go nextT (n - 1)
        p a = (< a) <$> getRandomR (0 :: Int, 99)
        w32 = putWord32le
        pQuote = 80
        maxPacketTimeDiff = 5
        maxPacketLen = 1000

printQuotePkt :: QuotePkt -> IO ()
printQuotePkt QuotePkt{..} =
    C.putStrLn $ timeS pktTime <> " " <> timeS acceptTime <> " " <> issueCode <> " "
        <> BS.concat (map (\(q, p) -> q <> "@" <> p <> " ") bids)
        <> BS.intercalate " " (map qtyPriceStr $ reverse asks)
    where
       qtyPriceStr (q, p) = q <> "@" <> p
        {- removeLeadingZeros, unused
        rlz a = let nlz = BS.length (BS.takeWhile (== 0x30) a)
                in if nlz == BS.length a then "0" else BS.drop nlz a -}

timeS :: Time -> BS.ByteString
timeS t = C.pack $ padShow (t_hours t)
            ++ padShow (t_minutes t)
            ++ padShow (t_seconds t)
            ++ padShow (t_centiseconds t)
    where
        padShow x = if x < 10 then '0':show x else show x

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
        t_hours = readInt $ BS.take 2 inp
      , t_minutes = readInt $ dropTake 2 2 inp
      , t_seconds = readInt $ dropTake 4 2 inp
      , t_centiseconds = readInt $ dropTake 6 2 inp
    }
    where
        readInt b = ((fromIntegral (BS.head b) - 0x30) * 10) +
                        (fromIntegral (BS.last b) - 0x30)

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

pcapGlobalHdrLen, quotePktLen, pcapPktHdrLen :: Int
pcapGlobalHdrLen = 24
pcapPktHdrLen = 16
quotePktLen = 215

pcapHdrMagic :: Word32
pcapHdrMagic = 0xa1b2c3d4

quotePktMagic :: BS.ByteString
quotePktMagic = "B6034"

pcapHdrParser :: Parser Bool
pcapHdrParser = do
    magic <- word32
    skip (pcapGlobalHdrLen - 4)
    return $ magic == pcapHdrMagic

quotePktParser :: Parser (Either Time QuotePkt)
quotePktParser = do
    pktTime <- (curry pcapTimeToTime) <$> word32 <*> word32
    pktLen <- fromIntegral <$> word32
    origLen <- fromIntegral <$> word32
    if origLen /= pktLen || pktLen < quotePktLen then do
        skip pktLen
        return (Left pktTime)
    else do
        skip (pktLen - quotePktLen)
        magic <- bytes 5
        if magic /= quotePktMagic then do
            skip (quotePktLen - 5)
            return (Left pktTime)
        else
            (Right . parseQuotePkt pktTime . (quotePktMagic <>)) <$> bytes (quotePktLen - 5)
