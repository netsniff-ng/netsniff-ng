-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Store where

import qualified Data.Map as M
import Val

run :: Action a -> a
run ( Action f ) = let ( s, x ) = f M.empty in x

new :: Val -> Action Addr
new v = Action $ \ s -> 
    let a = Addr ( M.size s )
    in  ( M.insert a v s , a )

get :: Addr -> Action Val
get a = Action $ \ s -> ( s , s M.! a )

put :: Addr -> Val -> Action ()
put a v = Action $ \ s -> ( M.insert a v s, () )


  
