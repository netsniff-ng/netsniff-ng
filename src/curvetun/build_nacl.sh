#!/bin/bash

# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2011 Emmanuel Roullit.
# Subject to the GPL, version 2.

cc="gcc"
nacl_dir="/tmp"
nacl_version="nacl-20110221"
nacl_suffix="tar.bz2"
nacl_base_url="http://hyperelliptic.org/nacl"
nacl_path="$nacl_dir/$nacl_version.$nacl_suffix"
nacl_build_dir="$1"

if test -z "$nacl_build_dir"; then
	echo "Please input the path where NaCl should be build"
	exit 1
fi

if ! test -d "$nacl_build_dir"; then
	mkdir "$nacl_build_dir"
fi

wget -O "$nacl_path" "$nacl_base_url/$nacl_version.$nacl_suffix"
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
