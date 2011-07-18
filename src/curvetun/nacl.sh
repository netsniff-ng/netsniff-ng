#!/bin/sh

file=http://hyperelliptic.org/nacl/nacl-20110221.tar.bz2

lib=libnacl.a
hdr1=crypto_box_curve25519xsalsa20poly1305.h
hdr2=crypto_scalarmult_curve25519.h
hdr3=crypto_hash_sha512.h
hdr4=crypto_verify_32.h
hdr5=crypto_auth_hmacsha512256.h

mkdir -p nacl include

if [ -e nacl/$lib -a      \
     -e include/$hdr1 -a  \
     -e include/$hdr2 -a  \
     -e include/$hdr3 -a  \
     -e include/$hdr4 -a  \
     -e include/$hdr5 ]; then
	echo "NaCl found!"
else
	echo "NaCl not found! Downloading and building (this takes some time) ..."

	rm -rf tmp
	mkdir -p tmp
	cd tmp

	wget -q -O- $file | bunzip2 | tar -xf - --strip-components 1

	./do

	cd ../
	cp tmp/build/*/lib/*/$lib nacl/
	cp tmp/build/*/include/*/$hdr1 include/
	cp tmp/build/*/include/*/$hdr2 include/
	cp tmp/build/*/include/*/$hdr3 include/
	cp tmp/build/*/include/*/$hdr4 include/
	cp tmp/build/*/include/*/$hdr5 include/

	echo "Done!"
fi

