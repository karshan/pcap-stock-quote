{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module QuoteParser where

import qualified Data.ByteString       as BS (ByteString, concat, drop, head,
                                              intercalate, last, take)
import qualified Data.ByteString.Char8 as C (pack, putStrLn)
import           Data.Monoid           ((<>))
import           GHC.Word              (Word32 (..))
import           Parser                (Parser, bytes, skip, word32, ensure)
import           Time                  (Time (..), pcapTimeToTime)
import           Util                  (dropTake)

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
    --ensure 16
    pTime <- (curry pcapTimeToTime) <$> word32 <*> word32
    pktLen <- fromIntegral <$> word32
    origLen <- fromIntegral <$> word32
    --ensure pktLen
    if origLen /= pktLen || pktLen < quotePktLen then do
        skip pktLen
        return (Left pTime)
    else do
        skip (pktLen - quotePktLen)
        magic <- bytes 5
        if magic /= quotePktMagic then do
            skip (quotePktLen - 5)
            return (Left pTime)
        else
            (Right . parseQuotePkt pTime . (quotePktMagic <>)) <$> bytes (quotePktLen - 5)

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
