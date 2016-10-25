{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module QuoteParser
  ( QuotePkt(..)
  , printQuotePkt
  , parseQuotePkt
  ) where

import qualified Data.ByteString as BS
       (ByteString, drop, head, intercalate, last, take, takeWhile,
        length, replicate)
import qualified Data.ByteString.Char8 as C (pack, putStrLn)
import Data.Monoid ((<>))
import Time (Time(..))
import Util (dropTake)

type QtyPrice = (BS.ByteString, BS.ByteString)

data QuotePkt = QuotePkt
  { pktTime :: !Time
  , acceptTime :: !Time
  , issueCode :: !BS.ByteString
  , bids :: [QtyPrice]
  , asks :: [QtyPrice]
  } deriving (Eq, Show)

parseAcceptTime :: BS.ByteString -> Time
parseAcceptTime inp =
  Time
  { t_hours = readInt $ BS.take 2 inp
  , t_minutes = readInt $ dropTake 2 2 inp
  , t_seconds = readInt $ dropTake 4 2 inp
  , t_centiseconds = readInt $ dropTake 6 2 inp
  }
  where
    readInt b =
      ((fromIntegral (BS.head b) - 0x30) * 10) +
      (fromIntegral (BS.last b) - 0x30)

-- The returned list is in reverse order w.r.t. the input stream
parseNQtyPrice :: Int -> BS.ByteString -> [QtyPrice]
parseNQtyPrice = go []
  where
    go acc 0 _ = acc
    go acc n inp =
      go ((dropTake 5 7 inp, BS.take 5 inp) : acc) (n - 1) (BS.drop 12 inp)

parseQuotePkt :: Time -> BS.ByteString -> QuotePkt
parseQuotePkt inPktTime rawPkt =
  QuotePkt
  { pktTime = inPktTime
  , acceptTime = parseAcceptTime $ dropTake 206 8 rawPkt
  , issueCode = dropTake 5 12 rawPkt
  , bids = parseNQtyPrice 5 $ BS.drop 29 rawPkt
  , asks = parseNQtyPrice 5 $ BS.drop 96 rawPkt
  }

printQuotePkt :: QuotePkt -> IO ()
printQuotePkt QuotePkt {..} =
  C.putStrLn $
  showTime pktTime <> " " <> showTime acceptTime <> " " <> issueCode <> " " <>
  BS.intercalate " " (map qtyPriceStr bids) <>
  " " <>
  BS.intercalate " " (map qtyPriceStr $ reverse asks)
  where
    qtyPriceStr (q, p) = padQty (rlz q) <> "@" <> padPrice (rlz p)
    rlz a =
      let nlz = BS.length $ BS.takeWhile (== 0x30) a
      in if nlz == BS.length a
           then "0"
           else BS.drop nlz a
    padQty a = BS.replicate (7 - BS.length a) 0x20 <> a
    padPrice a = a <> BS.replicate (5 - BS.length a) 0x20

showTime :: Time -> BS.ByteString
showTime t =
  C.pack $
  padShow (t_hours t) ++
  ":" ++
  padShow (t_minutes t) ++
  ":" ++ padShow (t_seconds t) ++ "." ++ padShow (t_centiseconds t)
  where
    padShow x =
      if x < 10
        then '0' : show x
        else show x
