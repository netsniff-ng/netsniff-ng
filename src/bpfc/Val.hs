-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Val where

import qualified Data.Map as M

newtype Addr = Addr Int deriving ( Show, Eq, Ord )
type Store = M.Map Addr Val

newtype Action a = Action ( Store -> ( Store, a ))

instance Monad ( Action ) where
    return v = Action $ \ s -> ( s, v )
    Action f >>= k = Action $ \ s0 ->
        let ( s1, v1 ) = f s0
            Action g = k v1
        in  g s1

data Val = ValInt Int
         | ValBool Bool
         | ValAddr Addr
         | ValUnit
         | ValTuple [ Val ]
         | ValFun ( Val -> CPS Val )
         | ValCont ( Continuation Val )
         | ValErr String
    deriving Show

type Continuation a = a -> Action Val
data CPS a = CPS ( Continuation a -> Action Val )

feed :: CPS a -> Continuation a -> Action Val
feed ( CPS s ) c = s c

lift :: Action a -> CPS a
lift action = CPS $ \ c -> action >>= \ x -> c x 

instance Monad CPS where
  CPS s >>= f = CPS $ \ c ->
         s ( \ x -> feed ( f x ) c )
  return x = CPS $ \ c -> c x       


instance Show (a -> b) where show f = "(function)"
