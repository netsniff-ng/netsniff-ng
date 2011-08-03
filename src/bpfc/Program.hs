-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Program where

import Exp

import Text.PrettyPrint.HughesPJ


type Def = (String, Exp)
type Defs = [ Def ]

data Program = Program Defs Exp

prog2exp :: Program -> Exp
prog2exp ( Program defs main ) = MultiLet defs main

instance Show Program where
    show ( Program binds main ) = render $ vcat 
         $ map ( \ (n,v) -> text "def" <+> text n <+> equals <+> out v )
         $ binds ++ [ ( "main", main) ]
