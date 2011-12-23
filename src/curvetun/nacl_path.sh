#!/bin/sh

#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2011 Emmanuel Roullit.
# Subject to the GPL, version 2.
#

<<POD

=head1 NAME

nacl_path.sh - Generate include file for CMake where path to NaCl are written

=head1 SYNOPSIS

nacl_path.sh <include_path> <lib_path>

=head1 DESCRIPTION

This script was written to faciliate NaCl building and
integration in the netsniff-g toolkit infrastructure.

It writes the given path to NaCl library and its header files in nacl_path.cmake.

The following file is then included by CMake to find NaCl
for the linking operation.

It is particulary useful to use it when NaCl has been previously built on
the target.

=head1 AUTHOR

Written by Emmanuel Roullit <emmanuel@netsniff-ng.org>

=cut

POD

nacl_include_path="$1"
nacl_lib_path="$2"

if test -z $nacl_include_path || test -z $nacl_lib_path; then
	echo "Please input the path where NaCl is like the following:"
	echo "./$0.sh <include_path> <lib_path>"
	exit 1
fi

echo "SET(NACL_INCLUDE_DIR $nacl_include_path)" > nacl_path.cmake
echo "SET(NACL_LIB_DIR $nacl_lib_path)" >> nacl_path.cmake
