{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Gen where

import           Control.Monad.IO.Class     (MonadIO, liftIO)
import           Control.Monad.Random.Class (MonadRandom, getRandomR)
import qualified Data.ByteString            as BS (appendFile, replicate,
                                                   writeFile)
import           Data.Monoid                ((<>))
import           QuoteParser                (pcapHdrMagic, quotePktLen,
                                             quotePktMagic, timeS)
import           Time                       (Time (..), addCentiSeconds,
                                             timeToPcapTime)
import           Util                       (putWord32le)

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
                        <> BS.replicate (fromIntegral $ pktLen - quotePktLen) 0x41
                        <> quotePktMagic <> BS.replicate 201 0x42
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
