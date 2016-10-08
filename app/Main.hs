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
word32le = \s ->
              (fromIntegral (s `BS.unsafeIndex` 3) `shiftl_w32` 24) .|.
              (fromIntegral (s `BS.unsafeIndex` 2) `shiftl_w32` 16) .|.
              (fromIntegral (s `BS.unsafeIndex` 1) `shiftl_w32`  8) .|.
              (fromIntegral (s `BS.unsafeIndex` 0) )

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

quotePktLen :: Int
quotePktLen = 215

parseAndPrintChunk :: BS.ByteString -> FoldState -> IO (FoldState, BS.ByteString)
parseAndPrintChunk chunk state =
    case state of
        GetGlobalHeader ->
            if BS.length chunk < 24 then
                return (GetGlobalHeader, chunk)
            else
                if word32le chunk == 0xa1b2c3d4 then
                    parseAndPrintChunk (BS.drop 24 chunk) GetPacket
                else
                    return (FailState "missing global header", "")
        GetPacket -> do
            if BS.length chunk < 16 then
                return (GetPacket, chunk)
            else do
                let tm = (word32le chunk, word32le (BS.drop 4 chunk))
                    pktlen = fromIntegral $ word32le (BS.drop 8 chunk)
                    origlen = fromIntegral $ word32le (BS.drop 12 chunk)
                if BS.length chunk < 16 + pktlen then
                    return (GetPacket, chunk) -- TODO optimise so we dont need to reparse tm pktlen origlen ? seems like not a big deal
                else
                    if origlen /= pktlen || pktlen < quotePktLen then
                        parseAndPrintChunk (BS.drop (16 + pktlen) chunk) GetPacket
                    else do
                        let pktStart = BS.drop (16 + pktlen - quotePktLen) chunk
                        if BS.take 5 pktStart /= "B6034" then do
                            parseAndPrintChunk (BS.drop (16 + pktlen) chunk) GetPacket
                        else do
                            liftIO $ C.putStrLn (BS.take quotePktLen pktStart)
                            parseAndPrintChunk (BS.drop (16 + pktlen) chunk) GetPacket
        FailState msg -> return (FailState msg, "")
