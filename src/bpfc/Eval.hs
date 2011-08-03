-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Eval where

import Exp
import Val
import Store
import With
import Exp.Multi

type Env = ( String -> Val )

extend env n v = 
     ( \ m -> if n == m then v else env m ) 

nullEnv :: Env
nullEnv = \ x -> error $ "value not bound: " ++ x

fix :: ( a -> a ) -> a
fix f = f ( fix f )

evaluate :: Env -> Exp -> CPS Val
evaluate env x = case x of
    Err msg -> return $ ValErr msg  
  
    MultiAbs {} -> evaluate env ( Exp.Multi.expand x )
    Abs n b -> 
      return $ ValFun ( \ v -> evaluate ( extend env n v ) b )
    
    -- Rec n b -> fix ( \ v -> evaluate ( extend env n v ) b )
    Rec n ( b @ MultiAbs {}) -> evaluate env ( Rec n $ Exp.Multi.expand b )
    Rec n ( Abs x b ) ->
        lift ( new ( ValErr "Rec" ) ) >>= \ addr ->
        with ( evaluate ( extend env "addr" $ ValAddr addr )
                        ( Abs x $ App ( Abs n b ) ( Get $ Ref "addr" ) ) ) $ \ v ->
        lift ( put addr v ) >>= \ () -> 
        return v

    MultiApp {} -> evaluate env ( Exp.Multi.expand x )
    App f a -> 
        with_fun ( evaluate env f ) $ \ fun ->
        with ( evaluate env a ) $ \ arg ->
        fun arg

    Ref n -> return $ env n
    
    MultiLet {} -> evaluate env ( Exp.Multi.expand x )
    Let n x b ->
        with ( evaluate env x ) $ \ a -> 
        evaluate ( extend env n a ) b

    ConstInt  i -> return $ ValInt  i
    ConstBool b -> return $ ValBool b

    Greater x y -> 
        with_int_int_to_bool ( evaluate env x ) ( evaluate env y ) ( > )
    Equal x y -> 
        with_int_int_to_bool ( evaluate env x ) ( evaluate env y ) ( == )

    Plus  x y -> 
        with_int_int_to_int ( evaluate env x ) ( evaluate env y ) ( + )      
    Minus  x y -> 
        with_int_int_to_int ( evaluate env x ) ( evaluate env y ) ( - )      
    Times x y -> 
        with_int_int_to_int ( evaluate env x ) ( evaluate env y ) ( * )      

    If b x y -> 
        with_bool ( evaluate env b ) $ \ b ->
        evaluate env $ if b then x else y

    New x ->
        with ( evaluate env x ) $ \ v ->
        lift ( new v ) >>= \ a -> 
        return $ ValAddr a
    Get x ->
        with_addr ( evaluate env x ) $ \ a -> 
        lift ( get a )
    Put x y -> 
        with_addr ( evaluate env x ) $ \ a -> 
        with ( evaluate env y ) $ \ v ->
        lift ( put a v ) >>= \ () -> 
        return $ ValUnit

    Print x ->  -- interpreter ignores this,
                -- runtime will actually print
        evaluate env x 
    
    Seq x y ->
        with ( evaluate env x ) $ \ a ->  
        with ( evaluate env y ) $ \ b ->  
        return b
      
    Label n b ->
        with_current_continuation $ \ c ->
        evaluate ( extend env n $ ValCont c ) b
    Jump x y -> 
        with_cont ( evaluate env x ) $ \ k ->
        with ( evaluate env y ) $ \ v ->
        CPS $ \ c -> k v

    Tuple xs -> case xs of
        [] -> return $ ValTuple []
        x : xs' -> with ( evaluate env x ) $ \ a -> 
            with_tuple ( evaluate env ( Tuple xs' ) ) $ \ as' -> 
            return $ ValTuple $ a : as'
    Nth i x -> with_tuple ( evaluate env x ) $ \ xs -> 
        if ( 0 <= i && i < length xs ) 
        then return $ xs !! i
        else return $ ValErr "tuple index out of range"

    _ -> error $ "Eval.evaluate does not handle " ++ show x

with_current_continuation k =
    CPS $ \ c -> feed ( k c ) c
                 
        
