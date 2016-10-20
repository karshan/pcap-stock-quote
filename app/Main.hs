{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Main where

import qualified Data.ByteString               as BS (ByteString, concat, drop,
                                                      intercalate, length, take)
import qualified Data.ByteString.Char8         as C (pack, putStrLn, unpack)
import qualified Data.ByteString.Lazy          as L (ByteString, readFile)
import qualified Data.ByteString.Lazy.Internal as L (ByteString (..))
import           Data.Heap                     (Entry (..), Heap)
import qualified Data.Heap                     as Heap
import           Data.Monoid                   ((<>))
import           GHC.Word                      (Word32 (..))
import           System.Environment            (getArgs)
import           Time                          (Time (..), centiSecondsDiff,
                                                pcapTimeToTime)
import           Util                          (dropTake, getWord32At,
                                                strictConsLazy, word32le)

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

printQuotePkt :: QuotePkt -> IO ()
printQuotePkt QuotePkt{..} =
    C.putStrLn $ timeS pktTime <> " " <> timeS acceptTime <> " " <> issueCode <> " "
        <> BS.concat (map (\(q, p) -> q <> "@" <> p <> " ") bids)
        <> BS.intercalate " " (map qtyPriceStr $ reverse asks)
    where
        timeS t = C.pack $ padShow (t_hours t) ++ ":"
                    ++ padShow (t_minutes t) ++ ":"
                    ++ padShow (t_seconds t) ++ "."
                    ++ padShow (t_centiseconds t)
        padShow x = if x < 10 then '0':show x else show x
        qtyPriceStr (q, p) = q <> "@" <> p
        {- removeLeadingZeros, unused
        rlz a = let nlz = BS.length (BS.takeWhile (== 0x30) a)
                in if nlz == BS.length a then "0" else BS.drop nlz a -}

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

pcapGlobalHdrLen, quotePktLen, pcapPktHdrLen :: Int
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

runParser :: L.ByteString -> Parser a -> Either String (a, L.ByteString)
runParser l p = go "" l
    where
        go x L.Empty =
            case p x of
                NotEnoughInput -> Left "NotEnoughInput"
                Done leftover a -> Right (a, L.Chunk leftover L.Empty)
                Error s -> Left s
        go x (L.Chunk y ys) =
            case p (x <> y) of
                NotEnoughInput -> go (x <> y) ys
                Done leftover a -> Right (a, strictConsLazy leftover ys)
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


