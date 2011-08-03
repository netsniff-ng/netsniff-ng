-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Type.Pretty where

import Type.Data

import Text.PrettyPrint.HughesPJ

out :: Type -> Doc
out t = case t of
    Int -> text "Int"
    Bool -> text "Bool"
    Func f a -> parens $ hsep [ out f, text "->", out a ]
    Tuple ts -> parens $ hsep $ punctuate comma $ map out ts

