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
       (ByteString, foldrChunks, readFile)
import Data.Heap (Entry(..), Heap)
import qualified Data.Heap as Heap
import GHC.Word (Word32(..))
import QuoteParser (QuotePkt(..), parseQuotePkt, printQuotePkt)
import Time (Time(..), centiSecondsDiff, pcapTimeToTime)
import Util (getWord32At)
import System.Environment (getArgs)

data FoldState
  = GetGlobalHeader 
  | GetPacket (Heap HeapEntry)
  | FailState String
  deriving (Eq,Show)

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
     s <- 
       execStateT (parseAndPrintChunks sort lbs)
                  (GetGlobalHeader,"")
     case s of
       (GetPacket h,_) -> foldMap (printQuotePkt . payload) h
       _ -> return ()

parseAndPrintChunks
  :: Bool -> L.ByteString -> StateT (FoldState,BS.ByteString) IO ()
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

pcapGlobalHdrLen, quotePktLen, pcapPktHdrLen
  :: Int
pcapGlobalHdrLen = 24

pcapPktHdrLen = 16

quotePktLen = 215

pcapHdrMagic :: Word32
pcapHdrMagic = 0xa1b2c3d4

quotePktMagic :: BS.ByteString
quotePktMagic = "B6034"

parseAndPrintChunk
  :: Bool -> BS.ByteString -> FoldState -> IO (FoldState,BS.ByteString)
parseAndPrintChunk sort chunk state = 
  case state of
    GetGlobalHeader -> 
      if BS.length chunk < pcapGlobalHdrLen
         then return (GetGlobalHeader,chunk)
         else if getWord32At 0 chunk == pcapHdrMagic
                 then parseAndPrintChunk sort
                                         (BS.drop pcapGlobalHdrLen chunk)
                                         (GetPacket Heap.empty)
                 else return (FailState "Not a pcap file","")
    GetPacket h -> 
      do if BS.length chunk < pcapPktHdrLen
            then return (GetPacket h,chunk)
            else do let pktTime = 
                          pcapTimeToTime 
                            (getWord32At 0 chunk,getWord32At 4 chunk)
                        pktLen = fromIntegral $ getWord32At 8 chunk
                        origLen = fromIntegral $ getWord32At 12 chunk
                        goNextPkt h' = 
                          parseAndPrintChunk sort
                                             (BS.drop (pcapPktHdrLen + pktLen) chunk)
                                             (GetPacket h')
                    if BS.length chunk < pcapPktHdrLen + pktLen
                       then return (GetPacket h,chunk)
                       else if origLen /= pktLen || pktLen < quotePktLen
                               then do if sort
                                          then do h' <- flushHeap pktTime h
                                                  goNextPkt h'
                                          else goNextPkt h
                               else do let quotePktStart = 
                                             BS.drop (pcapPktHdrLen + pktLen -
                                                      quotePktLen)
                                                     chunk
                                       if BS.take 5 quotePktStart /=
                                          quotePktMagic
                                          then do if sort
                                                     then do h' <- 
                                                               flushHeap pktTime h
                                                             goNextPkt h'
                                                     else goNextPkt h
                                          else do let quotePkt = 
                                                        parseQuotePkt 
                                                          pktTime
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
    FailState msg -> return (FailState msg,"")

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
