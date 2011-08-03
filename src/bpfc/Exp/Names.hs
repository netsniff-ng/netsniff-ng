-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Exp.Names where

import Exp.Data
import Exp.Multi

import Data.Set (Set)
import qualified Data.Set as Set
import Control.Monad ( guard )

import Control.Monad.State ( State )
import qualified Control.Monad.State as State



run :: Exp -> State [ String ] a  -> a
run x s = State.evalState s ( name_supply x )

fresh :: State [ String ] String
fresh = do 
    n : ns <- State.get
    State.put ns
    return n


-- | infinite stream of names that do not occur in Exp
name_supply :: Exp -> [ String ]
name_supply x = do
    let v = var x
    k <- [ 1 .. ]
    let name = "k" ++ show k
    guard $ not $ Set.member name v
    return name

-- | set of all identifiers that are mentioned
-- (mentioned = defined or used)
var :: Exp -> Set String
var x = case x of
    ConstInt i -> Set.empty
    ConstBool i -> Set.empty
    Ref n     -> Set.singleton n
    Let n x b -> Set.union ( Set.singleton n ) $ Set.union ( var x  ) $ var b 
    MultiLet {} -> var $ Exp.Multi.expand x
    Abs n b   -> Set.union ( Set.singleton n ) $  var b 
    MultiAbs {} -> var $ Exp.Multi.expand x
    App f a   -> Set.union ( var f ) ( var a ) 
    MultiApp {} -> var $ Exp.Multi.expand x
    Plus x y  -> Set.union ( var x ) ( var y ) 
    Minus x y  -> Set.union ( var x ) ( var y ) 
    Times x y  -> Set.union ( var x ) ( var y ) 
    Greater x y  -> Set.union ( var x ) ( var y ) 
    Equal x y  -> Set.union ( var x ) ( var y ) 
    Put x y -> Set.union ( var x ) ( var y )
    Get x -> var x
    New x -> var x
    Print x -> var x
    If b j n   -> Set.union ( var b) $ Set.union (var j) (var n)
    Nth i x -> var x
    Tuple xs -> Set.unions $ map var xs
    _ -> error $ "Exp.Names.var is undefined for " ++ show x



-- | set of free identifiers (= used, but not defined)
fvar :: Exp -> Set String
fvar x = case x of
    ConstInt i -> Set.empty
    ConstBool i -> Set.empty
    Ref n     -> Set.singleton n
    Let n x b -> Set.union ( fvar x  ) $ Set.delete n $ fvar b 
    MultiLet {} -> fvar $ Exp.Multi.expand x
    Abs n b   -> Set.delete n $  fvar b 
    MultiAbs {} -> fvar $ Exp.Multi.expand x
    App f a   -> Set.union ( fvar f ) ( fvar a ) 
    MultiApp {} -> fvar $ Exp.Multi.expand x
    Plus x y  -> Set.union ( fvar x ) ( fvar y ) 
    Minus x y  -> Set.union ( fvar x ) ( fvar y ) 
    Times x y  -> Set.union ( fvar x ) ( fvar y ) 
    Greater x y  -> Set.union ( fvar x ) ( fvar y ) 
    Equal x y  -> Set.union ( fvar x ) ( fvar y ) 
    Put x y -> Set.union ( fvar x ) ( fvar y )
    Get x -> fvar x
    New x -> fvar x
    Print x -> fvar x
    If b j n   -> Set.union ( fvar b) $ Set.union (fvar j) (fvar n)
    Nth i x -> fvar x
    Tuple xs -> Set.unions $ map fvar xs
    _ -> error $ "Exp.Names.fvar is undefined for " ++ show x


