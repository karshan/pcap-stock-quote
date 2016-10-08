{-# LANGUAGE MagicHash             #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE PartialTypeSignatures #-}
module Main where

import           Control.Monad.IO.Class    (liftIO)
import           Control.Monad.State       (StateT, evalStateT)
import           Control.Monad.State.Class (get, put)
import           Data.Bits                 ((.|.))
import qualified Data.ByteString           as BS (ByteString, append, drop,
                                                  length, take)
import qualified Data.ByteString.Char8     as C (putStrLn)
import qualified Data.ByteString.Lazy      as L (ByteString, foldrChunks,
                                                 readFile)
import qualified Data.ByteString.Unsafe    as BS (unsafeIndex)
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
  | GetPacket
  | FailState String
        deriving (Eq, Show)

main :: IO ()
main = do
    (fn:_) <- getArgs
    lbs <- L.readFile fn
    evalStateT (parseAndPrintChunks lbs) (GetGlobalHeader, "")

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
                    parseAndPrintChunk (BS.drop pcapGlobalHdrLen chunk) GetPacket
                else
                    return (FailState "Not a pcap file", "")
        GetPacket -> do
            if BS.length chunk < pcapPktHdrLen then
                return (GetPacket, chunk)
            else do
                let pktTime = (getWord32At 0 chunk, getWord32At 4 chunk)
                    pktLen = fromIntegral $ getWord32At 8 chunk
                    origLen = fromIntegral $ getWord32At 12 chunk
                    goNextPkt = parseAndPrintChunk (BS.drop (pcapPktHdrLen + pktLen) chunk) GetPacket
                if BS.length chunk < pcapPktHdrLen + pktLen then
                    return (GetPacket, chunk)
                else
                    if origLen /= pktLen || pktLen < quotePktLen then
                        goNextPkt
                    else do
                        let pktStart = BS.drop (pcapPktHdrLen + pktLen - quotePktLen) chunk
                        if BS.take 5 pktStart /= quotePktMagic then do
                            goNextPkt
                        else do
                            liftIO $ C.putStrLn (BS.take quotePktLen pktStart)
                            goNextPkt
        FailState msg -> return (FailState msg, "")
