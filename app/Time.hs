{-# LANGUAGE RecordWildCards #-}

module Time
  ( Time(..)
  , centiSecondsDiff
  , pcapTimeToTime
  ) where

import GHC.Word (Word32)

data Time = Time
  { t_hours :: !Int
  , t_minutes :: !Int
  , t_seconds :: !Int
  , t_centiseconds :: !Int
  } deriving (Eq, Ord, Show)

centiSecondsDiff :: Time -> Time -> Int
centiSecondsDiff a b =
  ((t_hours a - t_hours b) * 360000) + ((t_minutes a - t_minutes b) * 6000) +
  ((t_seconds a - t_seconds b) * 100) +
  (t_centiseconds a - t_centiseconds b)

-- also converts to JST (UTC+09:00)
pcapTimeToTime :: (Word32, Word32) -> Time
pcapTimeToTime (pktSec, pktUsec) =
  let sec = fromIntegral (pktSec `mod` 86400)
      (m', s) = sec `quotRem` 60
      (h, m) = m' `quotRem` 60
  in Time ((h + 9) `mod` 24) m s ((fromIntegral pktUsec) `div` 10000)
