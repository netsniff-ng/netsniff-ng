-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

{-# language NoMonomorphismRestriction #-}

module Exp.Parser.Parsec  where

import qualified Text.Parsec as P
import Data.Char

type Parser c a = P.Parsec [c] () a

parse :: Show c => Parser c a -> [c] -> Either String a
parse p cs = case P.parse p "input" cs of
    Left err -> Left ( show err )
    Right x -> Right x

satisfy = P.satisfy
many1 = P.many1
many = P.many
sepBy1 = P.sepBy1
sepBy = P.sepBy
(<|>) = (P.<|>)
(<?>) = (P.<?>)
try = P.try
getInput = P.getInput

next = satisfy ( const True )
eof = P.eof
reject = do satisfy ( const False ) ; return undefined
