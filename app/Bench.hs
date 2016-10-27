module Main where

import qualified AttoPar
import           Criterion.Main (bench, defaultMain, nfIO)
import qualified FoldrChunks
import qualified Lib
import qualified Binary
import qualified Data.ByteString.Lazy as L

main :: IO ()
main =
    let
        fn = "mdf-kospi200.20110216-0.pcap"
    in do
        lbs <- L.fromStrict . L.toStrict <$> L.readFile fn
        defaultMain [ bench "foldrchunks" $ nfIO (FoldrChunks.run' False lbs)
                    , bench "foldrchunks-sort" $ nfIO (FoldrChunks.run' True lbs)
                    , bench "myparsec" $ nfIO (Lib.runNormal (L.drop 24 lbs))
                    , bench "myparsec-sort" $ nfIO (Lib.runSort (L.drop 24 lbs))
                    , bench "attoparsec" $ nfIO (AttoPar.runNormal (L.drop 24 lbs))
                    , bench "attoparsec-sort" $ nfIO (AttoPar.runSort (L.drop 24 lbs))
                    , bench "binary" $ nfIO (Binary.run False (L.drop 24 lbs))
                    , bench "binary-sort" $ nfIO (Binary.run True (L.drop 24 lbs))
                    ]
