{-# LANGUAGE MagicHash #-}
module Util
    ( strictConsLazy
    , word32le
    , dropTake)
    where

import           Data.Bits                     ((.|.))
import qualified Data.ByteString               as BS (ByteString, drop, null,
                                                      take)
import qualified Data.ByteString.Lazy.Internal as L (ByteString (..))
import qualified Data.ByteString.Unsafe        as BS (unsafeIndex)
import           GHC.Base                      (Int (..), uncheckedShiftL#)
import           GHC.Word                      (Word32 (..))

strictConsLazy :: BS.ByteString -> L.ByteString -> L.ByteString
strictConsLazy b l =
    if BS.null b then
        l
    else
        L.Chunk b l

-- shiftl_w32 and word32le are from the binary package
-- https://hackage.haskell.org/package/binary-strict-0.2/src/src/Data/Binary/Strict/Get.hs
shiftl_w32 :: Word32 -> Int -> Word32
shiftl_w32 (W32# w) (I# i) = W32# (w `uncheckedShiftL#` i)

-- Read the first 4 bytes of a ByteString as a Word32
word32le :: BS.ByteString -> Word32
{-# INLINE word32le #-}
word32le = \s ->
              (fromIntegral (s `BS.unsafeIndex` 3) `shiftl_w32` 24) .|.
              (fromIntegral (s `BS.unsafeIndex` 2) `shiftl_w32` 16) .|.
              (fromIntegral (s `BS.unsafeIndex` 1) `shiftl_w32`  8) .|.
              (fromIntegral (s `BS.unsafeIndex` 0) )

dropTake :: Int -> Int -> BS.ByteString -> BS.ByteString
dropTake d t = BS.take t . BS.drop d


