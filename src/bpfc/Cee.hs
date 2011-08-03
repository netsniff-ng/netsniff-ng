-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

-- | the C backend

module Cee where

import Exp.Data
import Exp.Names
import Exp.Multi
import Program

import Text.PrettyPrint.HughesPJ
import Data.Set (Set)
import qualified Data.Set as Set


program :: Program -> Doc
program ( Program defs main ) = 
    let names = Set.unions $ map  var $ main : map snd defs
        functions = Set.fromList $ map ( \ (n, v) -> n ) defs
        registers = Set.difference names functions
        register_decls = vcat
            $ map ( \ r -> text "val" <+> text r <+> semi ) 
            $ Set.toList registers
        function_decls = vcat
            $ map ( \ (n,v) -> vcat
                [ hsep [ text "void", text n, text "()" ]
                , braces $ expression v <+> semi
                ] )
            $ defs ++ [ ( "main", main ) ]            
    in  vcat [ text "#include \"runtime.c\""
             , register_decls
             , function_decls
             ]

expression :: Exp -> Doc
expression x = case x of
    MultiLet {} -> expression $ Exp.Multi.expand x
    Let n v b -> vcat [ hsep [ text n, equals , expression v, semi ]
                      , expression b
                      ]
    -- ignores arguments ( must be r0, r1, ... )
    MultiApp (Ref f) as -> call ( "(" ++ f ++ ".function)" ) [ ]
    -- ignores arguments ( must be r0, r1, ...)
    MultiAbs ns b -> expression b
    Times l r -> call "times" $ map expression [ l, r ]
    Plus l r -> call "plus" $ map expression [ l, r ]
    Minus l r -> call "minus" $ map expression [ l, r ]
    ConstInt i -> text "int2val" <+> parens (text $ show i )
    Ref n -> text n 
    Nth i b -> call "nth" [ text ( show i ), expression b ] 
    Tuple as -> call "tuple" $  text ( show $ length as ) : map expression as 
    Print l -> call "print" [ expression l ]
    _ -> error $ "Cee.expression does not handle " ++ show x


call f as = text f <+> parens ( hsep $ punctuate comma as )
