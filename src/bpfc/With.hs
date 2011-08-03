-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module With where

import Val
import Store

with :: CPS Val -> ( Val -> CPS Val ) -> CPS Val
with a k = a >>= \ v -> case v of
    ValErr e -> return $ ValErr e
    v -> k v

with_int_int v w k =
    with_int v $ \ i ->
    with_int w $ \ j -> 
    k i j

with_int_int_to_bool v w k = 
    with_int_int v w $ \ i j -> return $ ValBool $ k i j

with_int_int_to_int v w k = 
    with_int_int v w $ \ i j -> return $ ValInt $ k i j

with_int :: 
  CPS Val -> ( Int -> CPS Val ) -> CPS Val
with_int a k = a >>= \ v -> case v of
    ValInt i -> k i
    v -> return $ ValErr $ "ValInt expected " ++ show v

with_bool :: 
  CPS Val -> ( Bool -> CPS Val ) -> CPS Val
with_bool a k = a >>= \ v -> case v of
    ValBool i -> k i
    v -> return $ ValErr $ "ValBool expected: " ++ show v

with_addr :: 
  CPS Val -> ( Addr -> CPS Val ) -> CPS Val
with_addr a k = a >>= \ v -> case v of
    ValAddr i -> k i
    v -> return $ ValErr $ "ValAddr expected: " ++ show v


with_cont :: 
  CPS Val -> ( Continuation Val -> CPS Val ) -> CPS Val
with_cont a k = a >>= \ v -> case v of
    ValCont i -> k i
    v -> return $ ValErr $ "ValCont expected: " ++ show v


with_fun :: CPS Val 
         -> ( ( Val -> CPS Val ) -> CPS Val ) 
         -> CPS Val
with_fun a k = a >>= \ v -> case v of
    ValFun fun -> k fun
    v -> return $ ValErr $ "ValFun expected: " ++ show v

with_tuple :: CPS Val 
         -> ( [ Val ] -> CPS Val ) 
         -> CPS Val
with_tuple a k = a >>= \ v -> case v of
    ValTuple xs -> k xs
    v -> return $ ValErr $ "ValTuple expected: " ++ show v
