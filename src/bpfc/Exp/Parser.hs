-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Exp.Parser 
( parse, complete_expression
) where

import Exp.Data
import Type.Parser ( typ )
import Exp.Parser.Common

instance Read Exp where
    readsPrec p cs = case parse embedded_expression cs of
        Right ( x, rest ) -> [ (x,rest) ]
        Left msg -> error msg

complete_expression :: Parser Char Exp
complete_expression = complete $ expression

embedded_expression :: Parser Char ( Exp, String )
embedded_expression = do
    x <- expression
    rest <- getInput
    return ( x, rest )

expression :: Parser Char Exp
expression = 
        do reserved "let" 
           binds <- braces $ flip sepBy1 ( expect ';' ) $ do
               name <- ident
               reservedOp "="
               def <- expression
               return ( name, def )
           reserved "in"    
           body <- expression
           return $ MultiLet binds body 
    <|> do reserved "letval" 
           (name, def) <- braces $ do
               name <- ident
               reservedOp "="
               def <- expression
               return ( name, def )
           reserved "in"    
           body <- expression
           return $ LetVal name def body
    <|> do reservedOp "\\"
           names <- many1 ident_with_type
           reservedOp "->"
           body <- expression
           return $ TypedMultiAbs names body 
    <|> operator_expression 
           [ [ (">", Greater), ("==", Equal) ]  
           , [ ("+", Plus), ("-", Minus) ]  
           , [ ("*", Times) ] 
           ] application 

ident_with_type = parens $ do
    i <- ident
    reservedOp "::"
    t <- Type.Parser.typ
    return ( i, t )

ident = try $ do
    w <- identifier
    whitespace
    if elem w [ "let", "letval", "in"
       	      , "if", "then", "else", "True", "False" 
	      , "err"
	      , "new", "get", "put", "seq"
              , "label", "jump"
              , "tuple", "nth"
              , "print"
	      ]
       then reject else return w

application = 
        do reserved "rec"
           (i, t) <- ident_with_type
           body <- atomic
           return $ TypedRec (i,t) body           
    <|> do reserved "err"
    	   msg <- ident
	   return $ Err msg
    <|> do reserved "new"
    	   x <- atomic
	   return $ New x 
    <|> do reserved "put"
    	   x <- atomic
	   y <- atomic
	   return $ Put x y
    <|> do reserved "get"
    	   x <- atomic
	   return $ Get x
    <|> do reserved "print"
    	   x <- atomic
	   return $ Print x
    <|> do reserved "seq"
    	   xs <- many1 atomic
	   return $ foldr1 Seq xs
    <|> do reserved "label"
           l <- ident
           x <- atomic
           return $ Label l x
    <|> do reserved "jump"
           x <- atomic
           y <- atomic
           return $ Jump x y
    <|> do reserved "if"  ; i <- expression
           reserved "then" ; t <- expression
           reserved "else" ; e <- expression
           return $ If i t e
    <|> do reserved "tuple"
           xs <- many atomic
           return $ Tuple xs
    <|> do reserved "nth"
           x <- number ; whitespace
           y <- atomic
           return $ Nth x y
    <|> do x : xs <- many1 atomic
           return $ if null xs then x else MultiApp x xs
      
atomic = parens expression
    <|> do n <- number ; whitespace ; return $ ConstInt n
    <|> do reserved "True" ; return $ ConstBool True       
    <|> do reserved "False" ; return $ ConstBool False 
    <|> do i <- ident ; return $ Ref i

operator_expression ops atomic = case ops of
    [] -> atomic
    here : lower -> do
        x <- operator_expression lower atomic
        oys <- many $ do
            o <- foldr1 (<|>) $ do
                ( c, op ) <- here
                return $ do reservedOp c ; return op
            y <- operator_expression lower atomic 
            return (o, y)
        return $ foldl ( \ x (o,y) -> o x y ) x oys
        
