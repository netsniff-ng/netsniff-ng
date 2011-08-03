-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Exp.Subst where

import Exp.Data
import Exp.Multi

import Data.Map ( Map )
import qualified Data.Map as Map

-- | replace free reference to name by expression
subst :: Map String Exp -> Exp -> Exp
subst f x = case x of
    Ref n -> case Map.lookup n f of
        Just v -> v 
        _ -> x
    ConstInt i -> ConstInt i
    ConstBool i -> ConstBool i
    Plus l r -> Plus ( subst f l ) ( subst f r )
    Minus l r -> Minus ( subst f l ) ( subst f r )
    Times l r -> Times ( subst f l ) ( subst f r )
    Greater l r -> Greater ( subst f l ) ( subst f r )
    Equal l r -> Equal ( subst f l ) ( subst f r )
    Get x -> Get ( subst f x )
    New x -> New ( subst f x )
    Put x y -> Put ( subst f x ) ( subst f y )
    If b j no -> If ( subst f b ) (subst f j) (subst f no) 
    App x y -> App ( subst f x ) ( subst f y )
    MultiApp x ys -> MultiApp ( subst f x ) ( map (subst f ) ys )
    Let n y b -> 
        let g = Map.delete n f
        in  Let n ( subst f y ) ( subst g b )
    MultiLet {} -> Exp.Multi.collect $ subst f $ Exp.Multi.expand x
    Abs n b -> 
        let g = Map.delete n f
        in  Abs n ( subst g b )
    MultiAbs ns b ->
        let g = foldr Map.delete f ns
        in  MultiAbs ns ( subst g b )
    Nth i b -> Nth i ( subst f b )
    Tuple xs -> Tuple $ map (subst f) xs
    _ -> error $ "Exp.subst is undefined for " ++ show x
