{-# LANGUAGE OverloadedStrings #-}
module Lib where

import           Control.Monad.Random          (evalRandT)
import qualified Data.ByteString.Lazy          as L (ByteString, readFile)
import qualified Data.ByteString.Lazy.Internal as L (ByteString (..))
import           Data.Heap                     (Entry (..), Heap)
import qualified Data.Heap                     as Heap
import           Gen                           (gen)
import           Parser                        (runParser)
import           QuoteParser                   (QuotePkt (..), pcapHdrParser,
                                                printQuotePkt, quotePktParser)
import           System.Environment            (getArgs)
import           System.Random                 (getStdGen)
import           Time                          (Time (..), centiSecondsDiff)

usage :: IO ()
usage = putStrLn "usage: ./pcap-stock-quote [-r] <pcap-file>"

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
