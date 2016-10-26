{-# LANGUAGE OverloadedStrings #-}

module Parser
  ( Parser(..)
  , ParserOut(..)
  , runParser
  , ensure
  , word32
  , skip
  , bytes
  ) where

import qualified Data.ByteString as BS
       (ByteString, drop, length, take)
import qualified Data.ByteString.Lazy.Internal as L
       (ByteString(..))
import Data.Monoid ((<>))
import GHC.Word (Word32)
import Util (strictConsLazy, word32le)

newtype Parser a = P
  { unP :: BS.ByteString -> ParserOut a
  }

data ParserOut a
  = NotEnoughInput
  | Done BS.ByteString
         a
  | Error String

instance Functor ParserOut where
  fmap f (Done l a) = Done l (f a)
  fmap _ NotEnoughInput = NotEnoughInput
  fmap _ (Error s) = Error s

instance Functor Parser where
  fmap f (P p) = P (fmap f . p)

instance Applicative Parser where
  pure a = P (\i -> Done i a)
  (P f) <*> (P g) =
    P
      (\i ->
         case f i of
           Done l a -> a <$> g l
           NotEnoughInput -> NotEnoughInput
           Error s -> Error s)

instance Monad Parser where
  (P f) >>= g =
    P
      (\i ->
         case f i of
           Done l a -> unP (g a) l
           NotEnoughInput -> NotEnoughInput
           Error s -> Error s)

runParser :: L.ByteString -> Parser a -> Either String (a, L.ByteString)
runParser l (P p) = go "" l
  where
    go x L.Empty =
      case p x of
        NotEnoughInput -> Left "NotEnoughInput"
        Done leftover a -> Right (a, L.Chunk leftover L.Empty)
        Error s -> Left s
    go x (L.Chunk y ys) =
      case p (x <> y) of
        NotEnoughInput -> go (x <> y) ys
        Done leftover a -> Right (a, strictConsLazy leftover ys)
        Error s -> Left s

ensure :: Int -> Parser ()
ensure n =
  P $ \i ->
    if BS.length i < n
      then NotEnoughInput
      else Done i ()

word32 :: Parser Word32
word32 = ensure 4 >> P (\i -> Done (BS.drop 4 i) (word32le i))

skip :: Int -> Parser ()
skip n = ensure n >> P (\i -> Done (BS.drop n i) ())

bytes :: Int -> Parser BS.ByteString
bytes n = ensure n >> P (\i -> Done (BS.drop n i) (BS.take n i))
