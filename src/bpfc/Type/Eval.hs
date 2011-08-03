-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Type.Eval where


import Exp
import Exp.Multi
import Type.Data

import qualified Exp.Pretty
import qualified Type.Pretty
import Text.PrettyPrint.HughesPJ

import Control.Monad.Trans.Error -- instance Monad (Either e) where

type Env = ( String -> Type )

extend env n v = 
     ( \ m -> if n == m then v else env m ) 

nullEnv :: Env
nullEnv = \ x -> error $ "value not bound: " ++ x


with computation k = computation >>= k

with_fun computation k = do
    t <- computation
    case t of
        Func f a -> k f a
        _ -> Left $ text "type must be function" <+> Type.Pretty.out t

with_int computation k = do
    t <- computation
    case t of 
        Int -> k
        _ -> Left $ text "type must be Int" <+> Type.Pretty.out t

with_tuple computation k = do
    t <- computation
    case t of 
        Type.Data.Tuple xs -> k xs
        _ -> Left $ text "type must be Tuple" <+> Type.Pretty.out t

with_bool computation k = do
    t <- computation
    case t of 
        Bool -> k
        _ -> Left $ text "type must be Bool" <+> Type.Pretty.out t

with_int_int_to_int l r k = 
    with_int l $ with_int r $ return Int 

evaluate :: Env -> Exp -> Either Doc Type
evaluate env x = case x of
  
    TypedMultiAbs {} -> evaluate env ( Exp.Multi.expand x )
    TypedAbs (n, t) b -> 
        with ( evaluate ( extend env n t ) b ) $ \ res -> 
            return ( Func t res )

    TypedRec (n, t) b ->
        with ( evaluate ( extend env n t ) b ) $ \ res -> 
        if res == t then return res 
        else Left $ vcat [ text "arg type of rec does not equal result type"
                         , text "expression" <+> Exp.Pretty.out x
                         , text "arg" <+> Type.Pretty.out t
                         , text "res" <+> Type.Pretty.out res
                         ]
        
    MultiApp {} -> evaluate env ( Exp.Multi.expand x )
    App f a -> 
        with_fun ( evaluate env f ) $ \ arg res ->
        with ( evaluate env a ) $ \ arg' -> 
            if arg == arg' 
            then return res
            else Left $ vcat [ text "wrong argument type"
                             , text "expression" <+> Exp.Pretty.out x
                             , text "expected" <+> Type.Pretty.out arg
                             , text "got" <+> Type.Pretty.out arg'
                             ]

    Ref n -> return $ env n
    
    MultiLet {} -> evaluate env ( Exp.Multi.expand x )
    Let n x b ->
        with ( evaluate env x ) $ \ a -> 
        evaluate ( extend env n a ) b

    ConstInt  i -> return $ Int 
    ConstBool b -> return $ Bool

    Print x -> with_int ( evaluate env x ) $ return $ Type.Data.Tuple []
    

    Plus  x y -> 
        with_int_int_to_int ( evaluate env x ) ( evaluate env y ) ( + )      
    Minus  x y -> 
        with_int_int_to_int ( evaluate env x ) ( evaluate env y ) ( - )      
    Times x y -> 
        with_int_int_to_int ( evaluate env x ) ( evaluate env y ) ( * )      

        

{-

    Greater x y -> 
        with_int_int_to_bool ( evaluate env x ) ( evaluate env y ) ( > )
    Equal x y -> 
        with_int_int_to_bool ( evaluate env x ) ( evaluate env y ) ( == )

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
-}

    Exp.Tuple xs -> case xs of
        [] -> return $ Type.Data.Tuple []
        x : xs' -> with ( evaluate env x ) $ \ a -> 
            with_tuple ( evaluate env ( Exp.Tuple xs' ) ) $ \ as' -> 
            return $ Type.Data.Tuple $ a : as'

    Nth i x -> with_tuple ( evaluate env x ) $ \ xs -> 
        if ( 0 <= i && i < length xs ) 
        then return $ xs !! i
        else Left $ text "tuple index out of range"

    _ -> error $ "Type.Eval.evaluate does not handle " ++ show x


                 
        
