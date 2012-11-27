#!/bin/sh

# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2011 Emmanuel Roullit.
# Subject to the GPL, version 2.

nacl_include_path="$1"
nacl_lib_path="$2"

if test -z $nacl_include_path || test -z $nacl_lib_path; then
	echo "Please input the path where NaCl is like the following:"
	echo "./$0.sh <include_path> <lib_path>"
	exit 1
fi

export NACL_INCLUDE_DIR=$nacl_include_path
export NACL_LIB_DIR=$nacl_lib_path

echo "export NACL_INCLUDE_DIR=$nacl_include_path" >> ~/.bashrc
echo "export NACL_LIB_DIR=$nacl_lib_path" >> ~/.bashrc
