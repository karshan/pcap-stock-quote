{-# LANGUAGE RecordWildCards #-}
module Time
    ( Time (..)
    , centiSecondsDiff
    , pcapTimeToTime
    , timeToPcapTime
    , addCentiSeconds
    )
    where

import           Data.DateTime         (fromGregorian)
import           Data.Time.Clock       (addUTCTime, diffTimeToPicoseconds)
import           Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import           GHC.Word              (Word32)

data Time = Time {
    t_hours        :: !Int
  , t_minutes      :: !Int
  , t_seconds      :: !Int
  , t_centiseconds :: !Int
} deriving (Eq, Ord, Show)

centiSecondsDiff :: Time -> Time -> Int
centiSecondsDiff a b =
    ((t_hours a - t_hours b) * 360000)
        + ((t_minutes a - t_minutes b) * 6000)
        + ((t_seconds a - t_seconds b) * 100)
        + (t_centiseconds a - t_centiseconds b)

addCentiSeconds :: Time -> Int -> Time
addCentiSeconds Time{..} n =
    let
        c = t_centiseconds + n
        s = t_seconds + (c `div` 100)
        m = t_minutes + (s `div` 60)
        h = t_hours + (m `div` 60)
    in
        Time h
            (m `mod` 60)
            (s `mod` 60)
            (c `mod` 100)

-- also converts to JST (UTC+09:00)
pcapTimeToTime :: (Word32, Word32) -> Time
pcapTimeToTime (pktSec, pktUsec) =
    let
        sec = fromIntegral (pktSec `mod` 86400)
        (m', s) = sec `quotRem` 60
        (h, m) = m' `quotRem` 60
    in
        Time ((h + 9) `mod` 24) m s ((fromIntegral pktUsec) `div` 10000)

timeToPcapTime :: Time -> (Word32, Word32)
timeToPcapTime Time{..} =
    let
        -- y m d unused see pcapTimeToTime
        base = utcTimeToPOSIXSeconds $ addUTCTime (-9 * 3600) $ fromGregorian 2016 10 10 t_hours t_minutes t_seconds
    in
        (fromIntegral $ (diffTimeToPicoseconds (realToFrac base)) `div` ((10 :: Integer) ^ (12 :: Integer)),
            fromIntegral $ t_centiseconds * 10000)
