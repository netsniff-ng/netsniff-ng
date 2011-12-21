#!/bin/sh

nacl_version="nacl-20110221"
nacl_build_dir="$1"

if test -z "$nacl_build_dir"; then
	echo "Please input the path where NaCl should be build"
	exit 1
fi

echo "Building NaCl (this takes a while) ..."

tar xjf "$nacl_version".tar.bz2 -C "$nacl_build_dir"
cd "$nacl_build_dir"/"$nacl_version"
./do
cd - > /dev/null

echo "Done!"

