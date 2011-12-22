#!/bin/sh

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

nacl_lib_path=$(dirname $(readlink -f $(find $nacl_build_dir -name libnacl.a)))
nacl_include_path=$(dirname $(readlink -f $(find $nacl_build_dir -name crypto_box.h)))

echo "SET(NACL_INCLUDE_DIR $nacl_include_path)" > nacl_path.cmake
echo "SET(NACL_LIB_DIR $nacl_lib_path)" >> nacl_path.cmake

echo "Done!"

