-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Exp.Parser.Common 

( module Exp.Parser.Common
, Parser, parse, getInput
, many, many1, sepBy, sepBy1
, (<|>), reject, try
)

where

import Exp.Parser.Parsec
import Data.Char

complete :: Show c => Parser c a -> Parser c a
complete p = do x <- p ; eof ; return x

digit :: Parser Char Int
digit = ( do
    c <- satisfy Data.Char.isDigit
    return $ fromIntegral 
           $ fromEnum c - fromEnum '0'
  ) <?> "[digit]"          
     
number :: Parser Char Int
number = do
    ds <- many1 digit    
    return $ foldl ( \ v d -> 10 * v + d) 0 ds

identifier :: Parser Char String
identifier = ( do
    x <- satisfy Data.Char.isAlpha 
    xs <- many $ satisfy Data.Char.isAlphaNum 
    return $ x : xs
  ) <?> "[identifier]"

whitespace :: Parser Char String
whitespace = many $ satisfy Data.Char.isSpace

reserved :: String -> Parser Char ()
reserved w = try ( do
    u <- identifier
    whitespace
    if u == w then return () else reject
  <?> w )

reservedOp :: String -> Parser Char ()
reservedOp w = try ( do
    u <- many1 $ satisfy ( \ c -> elem c "+-*/<>=\\,:" )
    whitespace
    if u == w then return () else reject
  <?> w )

expect :: Char -> Parser Char ()
expect c = do
    c <- satisfy ( \ d -> d == c )
    whitespace
    return ()
  <?> [ c ]

parens :: Parser Char a -> Parser Char a
parens p = do 
    expect '(' ; x <- p ; expect ')' ; return x
    
braces :: Parser Char a -> Parser Char a
braces p = do 
    expect '{' ; x <- p ; expect '}' ; return x


