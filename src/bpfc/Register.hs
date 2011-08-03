-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Register where

import Exp
import Program

import Control.Monad.State ( State )
import qualified Control.Monad.State as S

import Data.Map ( Map )
import qualified Data.Map as Map

import Control.Monad ( forM )

-- | rename arguments of global functions to r0, r1, ...
convert :: Program -> Program
convert ( Program defs main ) = 
    Program ( map ( \(n,v) -> (n, conv v)) defs ) ( conv main )

conv v = 
    flip S.evalState Map.empty $ evaluate v 

register :: String -> State ( Map String String ) String
register n = do
    m <- S.get
    let k = Map.size m
        n' = "r" ++ show k
    S.put $ Map.insert n n' m
    return n'

evaluate x = case x of
    MultiAbs ns b -> do
        ns' <- forM ns register
        b' <- evaluate b
        return $ MultiAbs ns' b'
    Let n v b -> do
        v' <- evaluate v
        n' <- register n
        b' <- evaluate b
        return $ Let n' v' b'
    MultiApp f as -> do
        f' <- evaluate f
        as' <- forM as evaluate
        return $ application f' as'
    Ref n -> do
        m <- S.get
        return $ Ref $ case Map.lookup n m of
            Nothing -> n -- global subroutine name (hopefully)
            Just n' -> n'
    Nth i b -> do b' <- evaluate b ; return $ Nth i b'
    Tuple xs -> do xs' <- forM xs evaluate ; return $ Tuple xs'
    Plus l r -> do l' <- evaluate l ; r' <- evaluate r ; return $ Plus l' r'
    Minus l r -> do l' <- evaluate l ; r' <- evaluate r ; return $ Minus l' r'
    Times l r -> do l' <- evaluate l ; r' <- evaluate r ; return $ Times l' r'
    Equal l r -> do l' <- evaluate l ; r' <- evaluate r ; return $ Equal l' r'
    Print l -> do l' <- evaluate l ; return $ Print l'
    If b y n -> do
        b' <- evaluate b ; y' <- evaluate y ; n' <- evaluate n 
        return $ If b y n
    ConstInt {} -> return x
    ConstBool {} -> return x
    _ -> error $ "Register.evaluate does not handle " ++ show x


application f src = 
    let r k = "r" ++ show k
        dest = map r [ 0 .. length src - 1 ]
        temps = filter ( \ n ->  not ( Ref n `elem` ( f : src ) ) )
              $ map r [ length src .. ]
        binds = zip temps ( f : src )
              ++ zip dest ( map Ref $  tail temps )
    in  MultiLet binds $ MultiApp ( Ref $ head temps ) ( map Ref dest )

