-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

import Exp 

import qualified Type.Pretty
import qualified Type.Eval

import Program ( prog2exp )
import Eval ( evaluate, nullEnv )
import Store ( run )
import Val ( feed )


-- import CPS.Simple ( transform )
import CPS.Meta ( transform )
import CC (cc)
import Lift (lift)
import Register ( convert )
import Cee ( program )

main = do
    cs <- getContents
    case parse complete_expression cs of
        Right x0 -> do
            let xt = Print x0

            heading "Text : P (typed)"
            print $ out xt

            heading "Typprüfung"
            case Type.Eval.evaluate Type.Eval.nullEnv xt of
                Right t -> print $ Type.Pretty.out t
                Left msg -> error $ show  msg

            let x = untype xt
            heading "Text : P (untyped)"
            print $ out x

            heading "Text : CPS(P)"
            let tx = transform x
            print $ out tx
            heading "Text : CC(CPS(P))"
            let ctx = cc tx
            print $ out ctx

            heading "Text : Lift(CC(CPS(P)))"
            let lctx = lift ctx
            print $ lctx

            heading "Text : Reg(Lift(CC(CPS(P))))"
            let rlctx = convert lctx
            print $ rlctx

            heading "Text : C-Back(Reg(Lift(CC(CPS(P)))))"
            let cee = Cee.program rlctx
            print $ cee

            heading "Wert : P"
            print $ run 
                  $ feed ( evaluate nullEnv x )
                         ( \ v -> return v )
            heading "Wert : CPS(P)"
            print $ run 
                  $ feed ( evaluate nullEnv tx )
                         ( \ v -> return v )
            heading "Wert : CC(CPS(P))"
            print $ run 
                  $ feed ( evaluate nullEnv ctx )
                         ( \ v -> return v )
            heading "Wert : Lift(CC(CPS(P)))"
            print $ run 
                  $ feed ( evaluate nullEnv $ prog2exp lctx )
                         ( \ v -> return v )
            
            heading "Wert : Reg(Lift(CC(CPS(P))))"
            print $ run 
                  $ feed ( evaluate nullEnv $ prog2exp rlctx )
                         ( \ v -> return v )
            
            heading "schreibe C-Back(Reg(Lift(CC(CPS(P))))) in main.c"
            writeFile "main.c" $ show cee


        Left err -> do
            putStrLn err
            
            
heading cs = do 
    putStrLn ""
    putStrLn cs
    putStrLn $ replicate ( length cs ) '-'
