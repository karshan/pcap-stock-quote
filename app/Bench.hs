module Main where

import qualified AttoPar
import           Criterion.Main (bench, defaultMain, nfIO)
import qualified FoldrChunks
import qualified Lib

main :: IO ()
main =
    let
        fn = "gen-50M.pcap"
    in
        defaultMain [ bench "foldrchunks" $ nfIO (FoldrChunks.run False fn)
                    , bench "foldrchunks-sort" $ nfIO (FoldrChunks.run True fn)
                    , bench "myparsec" $ nfIO (Lib.run False fn)
                    , bench "myparsec-sort" $ nfIO (Lib.run True fn)
                    , bench "attoparsec" $ nfIO (AttoPar.run False fn)
                    , bench "attoparsec-sort" $ nfIO (AttoPar.run True fn)
                    ]
