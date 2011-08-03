-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Exp.Data where

import Type.Data

data Exp = ConstInt Int | ConstBool Bool
         | Plus Exp Exp | Minus Exp Exp | Times Exp Exp
         | Greater Exp Exp | Equal Exp Exp
         | If Exp Exp Exp
         | Let String Exp Exp | LetVal String Exp Exp 
	 | Ref String
         | Abs String Exp 
         | TypedAbs (String, Type) Exp 
         | App Exp Exp
         | MultiAbs [String] Exp 
         | TypedMultiAbs [ (String, Type) ] Exp 
         | MultiApp Exp [Exp] 
         | MultiLet [(String, Exp)] Exp
         | Rec String Exp
         | TypedRec (String, Type) Exp
         | New Exp | Get Exp | Put Exp Exp | Seq Exp Exp
         | Label String Exp | Jump Exp Exp
	 | Err String
         | Tuple [ Exp ] | Nth Int Exp
         | Print Exp
     deriving ( Eq, Show )

untype :: Exp -> Exp
untype x = case x of
    ConstInt {} -> x
    ConstBool {} -> x
    TypedRec (n,t) b -> Rec n ( untype b )
    TypedMultiAbs nts b -> MultiAbs ( map fst nts ) $ untype b
    MultiApp f args -> MultiApp ( untype f ) ( map untype args )
    MultiLet nvs b -> 
        MultiLet ( map (\ (n,v) -> (n, untype v)) nvs ) $ untype b
    Print y -> Print ( untype y )
    Plus l r -> Plus ( untype l ) ( untype r )
    Minus l r -> Minus ( untype l ) ( untype r )
    Times l r -> Times ( untype l ) ( untype r )
    Greater l r -> Greater ( untype l ) ( untype r )
    If b y n -> If ( untype b) ( untype y ) ( untype n )
    Ref n -> Ref n
    Nth i t -> Nth i ( untype t )
    Exp.Data.Tuple xs -> Exp.Data.Tuple ( map untype xs )
    _ -> error $ "Exp.Data.untype does not handle: " ++ show x
