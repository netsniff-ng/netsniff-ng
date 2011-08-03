-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module CPS.Simple where

import Exp
import Exp.Names 
import Exp.Subst

import Control.Monad.State (State)

transform :: Exp -> Exp
transform x = Exp.Names.run x 
    $ do f <- evaluate x ; return $ App f $ Abs "x" ( Ref "x" )

evaluate :: Exp -> State [ String ] Exp
evaluate x = case x of
    ConstInt i -> do
        k <- fresh
        return $ Abs k ( app ( Ref k ) x )
    Ref i -> do
        k <- fresh 
        return $ Abs k ( app ( Ref k ) x )
    Plus l r -> prim2 Plus l r
    Minus l r -> prim2 Minus l r
    Times l r -> prim2 Times l r
    Abs n b -> do
        k <- fresh ; a <- fresh ; c <- fresh
        tb <- evaluate b
        return $  Abs k 
          $ Let a ( Abs n (Abs c (app tb (Ref c))))
          $ app ( Ref k ) ( Ref a )
    App l r -> do
        k <- fresh ; f <- fresh ;  a <- fresh
        tl <- evaluate l ; tr <- evaluate r
        return $   Abs k
          $ app tl $ Abs f
          $ app tr $ Abs a
          $ app ( app (Ref f) (Ref a) ) ( Ref k )
    _  -> error $ "CPS.Simple.evaluate is undefined for " ++ show x


prim2 op l r = do
    k <- fresh ; a <- fresh ; b <- fresh ; c <- fresh 
    tl <- evaluate l ; tr <- evaluate r
    return $  Abs k 
          $ app tl $ Abs a
          $ app tr $ Abs b
          $ Let c ( op ( Ref a) (Ref b) )
          $ app (Ref k) (Ref c)

-- | implements the "implicit let" rule
app f a = case f of
    Abs n b -> let' n a b
    _ -> App f a

-- | implements the "copy-prop" rule
let' n x b = case x of
    Ref {} -> subst n x b
    -- Abs {} -> subst n x b
    _ -> Let n x b

