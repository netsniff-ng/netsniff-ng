-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
-- Copyright 2011 Daniel Borkmann.
-- Subject to the GPL.
--
-- bpfc, a tiny Haskell nfl to bpf compiler

import System
import System.Console.GetOpt
import Data.Maybe ( fromMaybe )

main = do
    args <- getArgs
    let ( actions, nonOpts, msgs ) = getOpt RequireOrder options args
    opts <- foldl (>>=) (return defaultOptions) actions
    let Options {
        optInput = input,
        optOutput = output
    } = opts
    input >>= output

data Options = Options {
    optInput  :: IO String,
    optOutput :: String -> IO ()
}

defaultOptions :: Options
defaultOptions = Options {
    optInput  = getContents,
    optOutput = putStr
}

options :: [OptDescr (Options -> IO Options)]
options = [
    Option ['i'] ["in"] (ReqArg readInput "FILE") "Input nfl file to read",
    Option ['o'] ["out"] (ReqArg writeOutput "FILE") "Output BPF file to write",
    Option ['v'] ["version"] (NoArg showVersion) "Show version",
    Option ['h'] ["help"] (NoArg showHelp) "Show help"
 ]

showVersion _ = do
    putStrLn "\nbpfc 0.1, a tiny nfl to bpf compiler"
    putStrLn "http://www.netsniff-ng.org\n"
    putStrLn "Please report bugs to <bugs@netsniff-ng.org>"
    putStrLn "Copyright (C) 2011 Daniel Borkmann <daniel@netsniff-ng.org>"
    putStrLn "License: GNU GPL version 2"
    putStrLn "This is free software: you are free to change and redistribute it."
    putStrLn "There is NO WARRANTY, to the extent permitted by law.\n"
    exitWith ExitSuccess

showHelp _ = do
    putStrLn "\nbpfc 0.1, a tiny nfl to bpf compiler"
    putStrLn "http://www.netsniff-ng.org\n"
    putStrLn "Usage: bpfc [options]"
    putStrLn "  -i|--in <nfl>       nfl input file"
    putStrLn "  -o|--out <bpf>      BPF output file"
    putStrLn "  -v|--version        Show version"
    putStrLn "  -h|--help           Show this help\n"
    putStrLn "Example:"
    putStrLn "  bpfc -i prog.nfl -o out.bpf\n"
    putStrLn "Please report bugs to <bugs@netsniff-ng.org>"
    putStrLn "Copyright (C) 2011 Daniel Borkmann <daniel@netsniff-ng.org>"
    putStrLn "License: GNU GPL version 2"
    putStrLn "This is free software: you are free to change and redistribute it."
    putStrLn "There is NO WARRANTY, to the extent permitted by law.\n"
    exitWith ExitSuccess

-- todo
readInput arg opt = return opt { optInput = readFile arg }
writeOutput arg opt = return opt { optOutput = writeFile arg }

