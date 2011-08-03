-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Exp.Multi where

import Exp.Data

collect :: Exp -> Exp
collect x = case x of
    App f a -> collectApp f [a]
    Abs n b -> collectAbs [n] b
    Let n v b -> collectLet [(n,v)] b

collectApp :: Exp -> [Exp] -> Exp
collectApp x as = case x of
    App f a -> collectApp f (a : as)
    MultiApp f as' -> collectApp f (as' ++ as)
    _ -> MultiApp x as

collectAbs :: [String ] -> Exp -> Exp
collectAbs ns b = case b of
    Abs n c -> collectAbs ( ns ++ [n] ) c
    MultiAbs ns' c -> collectAbs (ns ++ ns') c
    _ -> MultiAbs ns b

collectLet :: [(String,Exp)] -> Exp -> Exp
collectLet nvs x = case x of
    Let n v b -> collectLet ( nvs ++ [(n,v)] ) b
    MultiLet nvs' b -> collectLet ( nvs ++ nvs' ) b
    _ -> MultiLet nvs x

expand :: Exp -> Exp
expand x = case x of
    MultiApp f as -> foldl App f as
    MultiAbs ns b -> foldr Abs b ns
    TypedMultiAbs ns b -> foldr TypedAbs b ns
    MultiLet nvs b -> foldr ( \ (n,v) b -> Let n v b ) b nvs

