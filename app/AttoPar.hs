module AttoPar where

import           Data.Attoparsec.ByteString.Lazy
import qualified Data.ByteString.Lazy            as L
import qualified Data.ByteString.Lazy.Internal   as L
import           Data.Heap                       (Entry (..), Heap)
import qualified Data.Heap                       as Heap
import           Data.Monoid
import           GHC.Word
import           Prelude                         hiding (take)
import           QuoteParser                     (QuotePkt (..), parseQuotePkt,
                                                  pcapGlobalHdrLen,
                                                  pcapHdrMagic, printQuotePkt,
                                                  quotePktLen, quotePktMagic)
import           Time
import           Util

run :: Bool -> String -> IO ()
run sort fn = do
    lbs <- L.readFile fn
    case parse pcapHdrParser lbs of
        Fail _ _ s -> putStrLn $ "pcapHdrParser failed: " ++ s
        Done _ False -> putStrLn "Error: not a pcap file"
        Done rest True ->
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
            case parse quotePktParser i of
                Done rest a ->
                    case a of
                        (Left time) -> do
                            h' <- flushHeap time h
                            go h' rest
                        (Right pkt) -> do
                            h' <- flushHeap (pktTime pkt) h
                            go (Heap.insert (Entry (acceptTime pkt) pkt) h') rest
                Fail _ _ s -> putStrLn $ "quotePktParser failed: " ++ s

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
    case parse quotePktParser i of
        Done rest a ->
            case a of
                (Left _) -> runNormal rest
                (Right pkt) -> printQuotePkt pkt >> runNormal rest
        Fail _ _ s -> putStrLn $ "quotePktParser failed: " ++ s

word32 :: Parser Word32
word32 =
    word32le <$> take 4

pcapHdrParser :: Parser Bool
pcapHdrParser = do
    magic <- word32
    _ <- take (pcapGlobalHdrLen - 4)
    return $ magic == pcapHdrMagic

quotePktParser :: Parser (Either Time QuotePkt)
quotePktParser = do
    pTime <- (curry pcapTimeToTime) <$> word32 <*> word32
    pktLen <- fromIntegral <$> word32
    origLen <- fromIntegral <$> word32
    if origLen /= pktLen || pktLen < quotePktLen then do
        _ <- take pktLen
        return (Left pTime)
    else do
        _ <- take (pktLen - quotePktLen)
        magic <- take 5
        if magic /= quotePktMagic then do
            _ <- take (quotePktLen - 5)
            return (Left pTime)
        else
            (Right . parseQuotePkt pTime . (quotePktMagic <>)) <$> take (quotePktLen - 5)
