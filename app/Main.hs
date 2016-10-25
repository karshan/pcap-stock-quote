{-# LANGUAGE MagicHash #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.State (StateT, execStateT)
import Control.Monad.State.Class (get, put)
import qualified Data.ByteString as BS
       (ByteString, append, drop, length, take)
import qualified Data.ByteString.Lazy as L
       (ByteString, foldrChunks, readFile, toStrict, take, drop)
import Data.Heap (Entry(..), Heap)
import qualified Data.Heap as Heap
import GHC.Word (Word32(..))
import QuoteParser (QuotePkt(..), parseQuotePkt, printQuotePkt)
import Time (Time(..), centiSecondsDiff, pcapTimeToTime)
import Util (getWord32At)
import System.Environment (getArgs)

type HeapEntry = Entry Time QuotePkt

usage :: IO ()
usage = putStrLn "usage: ./pcap-stock-quote [-r] <pcap-file>"

main :: IO ()
main = 
  do args <- getArgs
     case args of
       ("-r":fn:[]) -> run True fn
       (fn:"-r":[]) -> run True fn
       (fn:[]) -> run False fn
       _ -> usage

run :: Bool -> String -> IO ()
run sort fn = 
  do lbs <- L.readFile fn
     if getWord32At 0
                    (L.toStrict $ L.take 4 lbs) ==
        pcapHdrMagic
        then do (h,_) <- 
                  execStateT 
                    (parseAndPrintChunks sort
                                         (L.drop pcapGlobalHdrLen lbs))
                    (Heap.empty,"")
                foldMap (printQuotePkt . payload) h
        else putStrLn "Not a pcap file."

parseAndPrintChunks
  :: Bool -> L.ByteString -> StateT (Heap HeapEntry,BS.ByteString) IO ()
parseAndPrintChunks sort lbs = 
  L.foldrChunks 
    (\e a -> 
       do (state,leftover) <- get
          put =<<
            liftIO (parseAndPrintChunk sort
                                       (leftover `BS.append` e)
                                       state)
          a)
    (return ())
    lbs

pcapGlobalHdrLen, quotePktLen, pcapPktHdrLen :: Num a
                                             => a
pcapGlobalHdrLen = 24

pcapPktHdrLen = 16

quotePktLen = 215

pcapHdrMagic :: Word32
pcapHdrMagic = 0xa1b2c3d4

quotePktMagic :: BS.ByteString
quotePktMagic = "B6034"

parseAndPrintChunk
  :: Bool
  -> BS.ByteString
  -> Heap HeapEntry
  -> IO (Heap HeapEntry,BS.ByteString)
parseAndPrintChunk sort chunk h = 
  do if BS.length chunk < pcapPktHdrLen
        then return (h,chunk)
        else do let pktTime = 
                      pcapTimeToTime (getWord32At 0 chunk,getWord32At 4 chunk)
                    pktLen = fromIntegral $ getWord32At 8 chunk
                    origLen = fromIntegral $ getWord32At 12 chunk
                    goNextPkt h' = 
                      parseAndPrintChunk sort
                                         (BS.drop (pcapPktHdrLen + pktLen) chunk)
                                         h'
                if BS.length chunk < pcapPktHdrLen + pktLen
                   then return (h,chunk)
                   else if origLen /= pktLen || pktLen < quotePktLen
                           then do if sort
                                      then do h' <- flushHeap pktTime h
                                              goNextPkt h'
                                      else goNextPkt h
                           else do let quotePktStart = 
                                         BS.drop (pcapPktHdrLen + pktLen -
                                                  quotePktLen)
                                                 chunk
                                   if BS.take 5 quotePktStart /= quotePktMagic
                                      then do if sort
                                                 then do h' <- 
                                                           flushHeap pktTime h
                                                         goNextPkt h'
                                                 else goNextPkt h
                                      else do let quotePkt = 
                                                    parseQuotePkt pktTime
                                                                  (BS.take quotePktLen quotePktStart)
                                              if sort
                                                 then do h' <- 
                                                           flushHeap pktTime h
                                                         goNextPkt (Heap.insert 
                                                                      (Entry (acceptTime quotePkt)
                                                                             quotePkt)
                                                                      h')
                                                 else do printQuotePkt quotePkt
                                                         goNextPkt h

-- Print all packets in the heap that have accept times more than 3 seconds in the past from the
-- given time.
flushHeap
  :: Time -> Heap HeapEntry -> IO (Heap HeapEntry)
flushHeap t h = 
  case Heap.uncons h of
    Just (minE,rest) -> 
      if t `centiSecondsDiff` priority minE > 300
         then do printQuotePkt (payload minE)
                 flushHeap t rest
         else return h
    _ -> return h
