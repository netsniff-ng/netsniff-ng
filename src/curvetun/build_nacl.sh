#!/bin/sh

#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2011 Emmanuel Roullit.
# Subject to the GPL, version 2.
#

<<POD

=head1 NAME

build_nacl - build NaCl in the wanted build directory

=head1 SYNOPSIS

build_nacl <nacl_build_path>

=head1 DESCRIPTION

This script was written to faciliate NaCl building and
integration in the netsniff-g toolkit infrastructure.

It unpacks the content of contrib/nacl/nacl-20110221.tar.bz2
in the given build directory, builds it and output the path
to NaCl library and its header in nacl_path.cmake.

The following file is then included by CMake to find NaCl
for the linking operation.

=head1 AUTHOR

Written by Emmanuel Roullit <emmanuel@netsniff-ng.org>

=cut

POD

cc="gcc"
nacl_dir="../../contrib/nacl/"
nacl_version="nacl-20110221"
nacl_suffix="tar.bz2"
nacl_path="$nacl_dir/$nacl_version.$nacl_suffix"
nacl_build_dir="$1"

if test -z "$nacl_build_dir"; then
	echo "Please input the path where NaCl should be build"
	exit 1
fi

if ! test -d "$nacl_build_dir"; then
	mkdir "$nacl_build_dir"
fi

tar xjf "$nacl_path" -C "$nacl_build_dir"

$cc -Wall -O2 ./abiname.c -o ./abiname
arch="`./abiname`"
shorthostname=$(hostname | sed 's/\..*//' | tr -cd '[a-z][A-Z][0-9]')

echo "Building NaCl for arch $arch on host $shorthostname (grab a coffee, this takes a while) ..."

cd "$nacl_build_dir"/"$nacl_version"
./do
cd - > /dev/null

nacl_lib_path="$nacl_build_dir/$nacl_version/build/$shorthostname/lib/$arch"
nacl_include_path="$nacl_build_dir/$nacl_version/build/$shorthostname/include/$arch"

echo "NaCl lib path $nacl_lib_path"
echo "NaCl include path $nacl_include_path"

./nacl_path.sh "$nacl_include_path" "$nacl_lib_path"

echo "Done!"

