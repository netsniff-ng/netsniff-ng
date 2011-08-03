-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Type.Parser where

import Type.Data

import Exp.Parser.Common

instance Read Type where
    readsPrec p cs = case parse embedded_typ cs of
        Right (x, rest ) -> [ (x, rest) ]
        Left msg -> error msg

embedded_typ = do
    t <- typ
    rest <- getInput
    return ( t, rest )

typ :: Parser Char Type
typ =  function

function :: Parser Char Type
function = do
    ts <- sepBy1 atomic ( reservedOp "->" )
    return $ foldr1 Func ts

atomic :: Parser Char Type
atomic = tuple
     <|> do reserved "Int" ; return Int
     <|> do reserved "Bool" ; return Bool

tuple :: Parser Char Type
tuple = parens $ do
    ts <- sepBy function ( reservedOp "," )
    return $ case ts of
         [ t ] -> t
         _     -> Tuple ts
