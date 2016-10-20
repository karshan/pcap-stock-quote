module Time
    ( Time (..)
    , centiSecondsDiff
    , pcapTimeToTime)
    where

import           Data.DateTime         (toGregorian)
import           Data.Time.Clock       (addUTCTime)
import           Data.Time.Clock.POSIX (posixSecondsToUTCTime)
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

-- also converts to JST (UTC+09:00)
pcapTimeToTime :: (Word32, Word32) -> Time
pcapTimeToTime (pktSec, pktUsec) =
    let (_, _, _, hours, minutes, seconds) = toGregorian $ addUTCTime (9 * 3600) $ posixSecondsToUTCTime $ fromIntegral pktSec
    in Time hours minutes seconds ((fromIntegral pktUsec) `div` 10000)
