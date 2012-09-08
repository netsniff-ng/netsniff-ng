#!/bin/sh

version=1.4.8

wget http://www.maxmind.com/download/geoip/api/c/GeoIP-$version.tar.gz
tar xvf GeoIP-$version.tar.gz
cd GeoIP-$version && ./configure --prefix=/usr/ && make && make check && make install
../../../scripts/geoip-database-update
