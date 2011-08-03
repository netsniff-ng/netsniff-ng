-- netsniff-ng - the packet sniffing beast
-- By Daniel Borkmann <daniel@netsniff-ng.org>
--
-- Code written by:
-- Copyright 2010 Johannes Waldmann <waldmann@imn.htwk-leipzig.de>
-- Subject to the GPL.

module Type.Data where

data Type = Int | Bool 
          | Func Type Type
          | Tuple [ Type ]
	  | Addr Type
    deriving ( Eq, Show )
