--
-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
-- Copyright 2010 Daniel Borkmann.
-- Subject to the GPL.
--

-- Part of bpfgen-ng.hs

module Parser where

import Data.Char

data Parser c a = Parser ( [c] -> [ (a, [c]) ] )
 
instance Monad ( Parser c ) where     
	return x = Parser $ \ s -> [ (x, s) ]
	Parser f >>= g = Parser $ \ s -> do 
		( a, t ) <- f s
		let Parser h = g a 
		h t

parse :: Parser c a -> [c] -> [(a, [c])]
parse (Parser f) s = f s

next :: Parser c c
next = Parser $ \ s -> case s of
	[] -> []
	x : xs -> [ (x, xs) ]

reject = Parser $ \ s -> []

satisfy :: ( c -> Bool ) -> Parser c c
satisfy p = do
	x <- next
	if p x then return x else reject

(<|>) :: Parser c a -> Parser c a -> Parser c a
Parser f <|> Parser g = Parser $ \ s -> 
	case f s of [] -> g s ; result -> result

many1, many :: Parser c a -> Parser c [a]
many1 p = do x <- p; xs <- many p; return (x:xs)
many  p = many1 p <|> return [] 

digit :: Parser Char Int
digit = do
	c <- satisfy Data.Char.isDigit
	return $ fromIntegral 
		$ fromEnum c - fromEnum '0'
               
number :: Parser Char Int
number = do
	ds <- many1 digit    
	return $ foldl ( \ v d -> 10 * v + d) 0 ds

identifier :: Parser Char String
identifier = do
	x <- satisfy Data.Char.isAlpha
	xs <- many $ satisfy Data.Char.isAlphaNum
	return $ x : xs

whitespace :: Parser Char String
whitespace = many $ satisfy Data.Char.isSpace

expect :: Char -> Parser Char ()
expect c = do
	c <- satisfy ( \ d -> d == c )
	whitespace
	return ()

reserved :: String -> Parser Char ()
reserved w = do
	u <- identifier
	whitespace
	if u == w then return () else reject

reservedOp :: String -> Parser Char ()
reservedOp w = do
	u <- many1 $ satisfy ( \ c -> elem c "+-*/<>=\\" )
	whitespace
	if u == w then return () else reject

parens :: Parser Char a -> Parser Char a
parens p = do 
	expect '(' ; x <- p ; expect ')' ; return x
    
braces :: Parser Char a -> Parser Char a
braces p = do 
	expect '{' ; x <- p ; expect '}' ; return x

sepBy, sepBy1 :: Parser c a -> Parser c sep -> Parser c [a]
sepBy  p sep = sepBy1 p sep <|> return []
sepBy1 p sep = do
	x <- p
	xs <- ( do sep ; sepBy1 p sep ) <|> return []
	return $ x : xs
