#!/bin/bash

version=1.4.8

wget http://www.maxmind.com/download/geoip/api/c/GeoIP-$version.tar.gz
tar xvf GeoIP-$version.tar.gz
cd GeoIP-$version && ./configure --prefix=/usr/ && make && make check && make install
cp libGeoIP/GeoIPUpdate.h /usr/include/
cp libGeoIP/GeoIP.h /usr/include/
cp libGeoIP/GeoIPCity.h /usr/include/
cd -
../../contrib/scripts/geoip-database-update
