-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module CPS.Meta where

import Exp
import Exp.Names 
import Exp.Subst
import Exp.Multi

import Control.Monad.State (State)
import qualified Control.Monad.State as State

transform x = Exp.Names.run x 
     $ evaluate x ( \ e -> return e )

type Cont = Exp -> State [ String ] Exp

evaluate :: Exp -> ( Cont -> State [ String ] Exp )
evaluate x k = case x of
    ConstInt i -> k x
    ConstBool i -> k x
    Ref i -> k x

    Plus  l r -> prim2 Plus  l r k
    Minus l r -> prim2 Minus l r k
    Times l r -> prim2 Times l r k
    Greater l r -> prim2 Greater l r k
    Equal l r -> prim2 Equal l r k

    New x -> prim1 New x k
    Get x -> prim1 Get x k
    Put x y -> prim2 Put x y k
    Print x -> prim1 Print x k

    Nth i x -> prim1 (Nth i) x k
    Tuple xs -> primN Tuple xs k

    -- Abs {} -> evaluate ( Exp.Multi.collect x ) k
    MultiAbs ns b -> do
        c <- fresh
        tb <- evaluate b $ id2mc c
        a <- fresh ; ka <- k ( Ref a )
        return 
          $ MultiLet [ (a , MultiAbs ( ns ++ [ c ] )  tb ) ]
          $ ka

    -- App {} -> evaluate ( Exp.Multi.collect x ) k
    MultiApp l rs -> 
        ( evaluate l ) $ \ f ->
        ( evaluateMany rs ) $ \ as -> do
            mk <- mc2exp k
            c <- fresh
            return $ MultiLet [(c, mk)] $ MultiApp f ( as ++ [ Ref c ] )

    Let n x b -> 
        ( evaluate x ) $ \ tx -> do
            tb <- evaluate b k
            return $ MultiLet [(n,tx)] tb
    MultiLet nxs b -> evaluate ( Exp.Multi.expand x ) k

    If b j n -> evaluate b $ \ tb -> do
        c <- fresh
        tj <- evaluate j $ id2mc c
        tn <- evaluate n $ id2mc c
        mk <- mc2exp k
        return $ Let c mk $ If tb tj tn
            
    _  -> error $ "CPS.Meta.evaluate is undefined for " ++ show x

id2mc c e = do
    return ( MultiApp (Ref c) [e]  )

mc2exp k = do
    c <- fresh
    mk <- k ( Ref c )
    return $ MultiAbs [c] mk

prim1 op l k = 
    evaluate l $ \ a -> do
    c <- fresh 
    kc <- k ( Ref c )
    return $ MultiLet [(c , op a )] kc

prim2 op l r k = 
    evaluate l $ \ a -> 
    evaluate r $ \ b -> do
    c <- fresh 
    kc <- k ( Ref c )
    return $ MultiLet [ (c, op a b ) ] kc

evaluateMany xs k = case xs of
    [] -> k []
    x : xs' -> 
        evaluate x $ \ a -> 
        evaluateMany xs' $ \ as -> 
        k (a : as)

primN op xs k = 
    evaluateMany xs $ \ as -> do
    c <- fresh 
    kc <- k ( Ref c )
    return $ MultiLet [(c , op as )] kc


