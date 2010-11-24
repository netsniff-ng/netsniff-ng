--
-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
-- Copyright 2010 Daniel Borkmann.
-- Subject to the GPL.
--

import Parser ( parse )
-- This will become a Berkeley Packet Filter code generator
-- TODO: AST and evaluation, optimization and so on

main = do
	cs <- getContents
	case parse expression cs of
		[ (x, "") ] -> do
		putStrLn "bpfgen expression:"
		print x
		putStrLn "bpfgen evaluation:"
		print $ run $ evaluate undefined x
