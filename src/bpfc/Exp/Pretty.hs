-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Exp.Pretty where

import Exp.Data
import Exp.Multi
import qualified Type.Pretty

import Text.PrettyPrint.HughesPJ

out :: Exp -> Doc
out x = case x of
    ConstInt i -> text $ show i
    ConstBool i -> text $ show i

    Plus l r -> parens $ hsep [ out l, text "+", out r ]
    Minus l r -> parens $ hsep [ out l, text "-", out r ]
    Times l r -> parens $ hsep [ out l, text "*", out r ]
    Greater l r -> parens $ hsep [ out l, text ">", out r ]
    Equal l r -> parens $ hsep [ out l, text "==", out r ]
    
    Put x y -> hsep [ text "put", out x, parens ( out y ) ]
    Get x -> hsep [ text "get", parens ( out x ) ]
    New x -> hsep [ text "new",  parens ( out x ) ]
    Print x -> hsep [ text "print",  parens ( out x ) ]

    Ref n -> text n

    Let {} -> out $ Exp.Multi.collect x 
    MultiLet nvs b  -> 
        vcat [ text "let" <+> braces ( vcat $ punctuate semi
                                     $ map (\(n,v)-> text n <+> text "=" <+> out v ) nvs )
             , text "in" <+> out b
             ]

    App {} -> out $ Exp.Multi.collect x
    MultiApp f as -> 
        out f <+> fsep ( map ( parens . out ) as )

    -- Abs {} -> out $ Exp.Multi.collect x
    MultiAbs ns b -> 
        parens $ text "\\" <+> fsep ( map text ns ) <+> text "->" <+> out b 

    TypedMultiAbs ns b -> 
        parens $ text "\\" <+> 
            fsep ( map ( \ (n,t) -> parens $ hsep [ text n, text "::", Type.Pretty.out t ] ) ns ) <+> text "->" <+> out b 

    If c y n -> fsep [ text "if" <+> out c
                     , text "then" <+> out y
                     , text "else" <+> out n
                     ]
    
    Nth i x -> text "nth" <+> fsep [ text ( show i ), parens ( out x ) ]
    Tuple xs -> text "tuple" <+> hsep ( map ( parens . out ) xs )

    Rec n b -> parens $ fsep [ text "rec", text n, out b ]
    TypedRec (n,t) b -> parens $ fsep [ text "rec"
                                      , parens ( hsep [ text n, text "::", Type.Pretty.out t ] )
                                      , out b ]

    _ -> error $ "Exp.Pretty.out does not handle " ++ show x 
