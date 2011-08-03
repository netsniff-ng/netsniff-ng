-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

-- | Closure Conversion.
-- input: any Exp.
-- output: equivalent Exp where all abstractions are closed.

module CC where

import Exp
import Exp.Names
import Exp.Subst
import Exp.Multi

import Data.Map ( Map )
import qualified Data.Map as Map

import Data.Set ( Set )
import qualified Data.Set as Set

cc :: Exp -> Exp
cc x = case x of

    -- Abs {} -> cc $ Exp.Multi.collect x
    MultiAbs ns b -> 
        let vs = Set.toList $ fvar x
            b' = multiLet ( do
                  ( k, v ) <- zip [ 1 .. ] vs
                  return ( v, Nth k ( Ref "clo" ) )
               ) $ cc b
        in  Tuple $ MultiAbs ( "clo" : ns ) b'
                 : map Ref vs

    -- App {} -> cc $ Exp.Multi.collect x
    MultiApp f as -> 
        let u = head $ name_supply x
        in  MultiLet [ ( u,  Nth 0 $ cc f ) ]
            $ MultiApp ( Ref u ) $  cc f : map cc as

    Let {} -> cc $ Exp.Multi.collect x
    MultiLet nvs b -> 
        MultiLet ( map ( \(n,v) -> (n, cc v)) nvs) (cc b)

    Ref n -> x
    ConstInt i -> x
    ConstBool b -> x
    Plus l r -> Plus (cc l) (cc r)
    Minus l r -> Minus (cc l) (cc r)
    Times l r -> Times (cc l) (cc r)
    Equal l r -> Equal (cc l) (cc r)

    Nth i t -> Nth i (cc t )
    Tuple xs -> Tuple ( map cc xs )

    Print l -> Print ( cc l )

    If b y n -> If (cc b) (cc y) (cc n)

    _ -> error $ "CC.cc does not handle " ++ show x


multiLet [] b = b ; multiLet nvs b = MultiLet nvs b
