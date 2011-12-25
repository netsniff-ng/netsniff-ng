#!/bin/bash

#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2011 Emmanuel Roullit.
# Copyright 2011 Daniel Borkmann.
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

echo "Building NaCl (this takes a while) ..."

tar xjf "$nacl_path" -C "$nacl_build_dir"
cd "$nacl_build_dir"/"$nacl_version"
./do
cd - > /dev/null

nacl_lib_vers="`find $nacl_build_dir -name libnacl.a`"
nacl_inc_vers="`find $nacl_build_dir -name crypto_box.h`"
nacl_build_arch="`uname -m`"
nacl_use_arch=""
nacl_use_inc=""

for i in $nacl_lib_vers; do
	if [[ $i =~ $nacl_build_arch ]]; then
		nacl_use_arch=$i
	# x86_64/amd64 name confusion
	elif [[ $i =~ "amd64" ]]; then
		if [[ "x86_64" =~ $nacl_build_arch ]]; then
			nacl_use_arch=$i
		fi
	elif [[ $i =~ "x86_64" ]]; then
		if [[ "amd64" =~ $nacl_build_arch ]]; then
			nacl_use_arch=$i
		fi
	fi
done

for i in $nacl_inc_vers; do
	if [[ $i =~ $nacl_build_arch ]]; then
		nacl_use_inc=$i
	# x86_64/amd64 name confusion
	elif [[ $i =~ "amd64" ]]; then
		if [[ "x86_64" =~ $nacl_build_arch ]]; then
			nacl_use_inc=$i
		fi
	elif [[ $i =~ "x86_64" ]]; then
		if [[ "amd64" =~ $nacl_build_arch ]]; then
			nacl_use_inc=$i
		fi
	fi
done

nacl_lib_path="`readlink -f $nacl_use_arch | xargs dirname`"
nacl_include_path="`readlink -f $nacl_use_inc | xargs dirname`"

echo "Path for linking: $nacl_lib_path"
echo "Path for including: $nacl_include_path"

./nacl_path.sh "$nacl_include_path" "$nacl_lib_path"

echo "Done!"

