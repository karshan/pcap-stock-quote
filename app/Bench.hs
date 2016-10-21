module Main where

import           Criterion.Main (bench, defaultMain, nfIO)
import qualified FoldrChunks
import qualified Lib

main :: IO ()
main =
    defaultMain [ bench "mdf-kospi-normal" $ nfIO (Lib.run False "mdf-kospi200.20110216-0.pcap")
                , bench "mdf-kospi-sort" $ nfIO (Lib.run True "mdf-kospi200.20110216-0.pcap")
                , bench "mdf-kospi-normal-foldrchunks" $ nfIO (FoldrChunks.run False "mdf-kospi200.20110216-0.pcap")
                , bench "mdf-kospi-sort-foldrchunks" $ nfIO (FoldrChunks.run True "mdf-kospi200.20110216-0.pcap")
                , bench "gen-100M-normal-foldrchunks" $ nfIO (FoldrChunks.run False "gen-100M.pcap")
                , bench "gen-100M-sort-foldrchunks" $ nfIO (FoldrChunks.run True "gen-100M.pcap")
                , bench "gen-100M-normal" $ nfIO (Lib.run False "gen-100M.pcap")
                , bench "gen-100M-sort" $ nfIO (Lib.run True "gen-100M.pcap")
                ]
