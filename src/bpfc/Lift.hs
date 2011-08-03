-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Lift where

import Exp
import Exp.Multi
import Exp.Subst
import Program

import qualified Control.Monad.State as S
import qualified Data.Map as Map


lift :: Exp -> Program
lift x = flip S.evalState [] $ do
    main <- evaluate x
    defs <- S.get
    return $ Program defs main

evaluate :: Exp -> S.State Defs Exp
evaluate x = case x of
    ConstInt {} -> return x
    ConstBool {} -> return x
    Ref {} -> return x

    MultiLet {} -> evaluate $ Exp.Multi.expand x
    Let n v b -> case v of
        MultiAbs {} -> do
            v' <- evaluate v
            evaluate $ subst ( Map.fromList [ (n, v') ] ) b
        _ -> do v' <- evaluate v ; b' <- evaluate b ; return $ Let n v' b'

    MultiAbs ns c -> do
        c' <- evaluate c
        defs <- S.get
        let glob = "g" ++ show ( length defs )
        S.put $ defs ++ [ (glob, MultiAbs ns c' ) ]
        return $ Ref glob

    MultiApp f as -> 
        evaluate f >>= \ x ->
        evaluateMany as >>= \ xs -> 
        return $ MultiApp x xs
        
    If b y n -> do
        b' <- evaluate b
        y' <- evaluate y
        n' <- evaluate n
        return $ If b' y' n'

    Plus l r -> do x <- evaluate l ; y <- evaluate r ; return $ Plus l r
    Minus l r -> do x <- evaluate l ; y <- evaluate r ; return $ Minus l r
    Times l r -> do x <- evaluate l ; y <- evaluate r ; return $ Times l r
    Equal l r -> do x <- evaluate l ; y <- evaluate r ; return $ Equal l r
    Nth i r -> do x <- evaluate r ; return $ Nth i x
    Tuple xs -> evaluateMany xs >>= \ as -> return $ Tuple as
    Print l -> do x <- evaluate l ; return $ Print x

    _ -> error $ "Lift.evaluate does not handle: " ++ show x


evaluateMany [] = return []
evaluateMany (a : as) = 
    evaluate a >>= \ x -> 
    evaluateMany as >>= \ xs -> 
    return $ x : xs
