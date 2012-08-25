#
# netsniff-ng - the packet sniffing beast
# By Daniel Borkmann <daniel@netsniff-ng.org>
# Copyright 2012 Daniel Borkmann <daniel@netsniff-ng.org>.
# Subject to the GPL, version 2.
#

include(CheckCSourceRuns)

check_c_source_runs("
#include <stdlib.h>
#include <GeoIP.h>
#include <GeoIPCity.h>

int main(int argc, char *argv[])
{
    int t1, t2;
    t1 = GEOIP_CITY_EDITION_REV1_V6;
    t2 = GEOIP_COUNTRY_EDITION_V6;
    exit(0);
}" GEOIPV6_RUN_RESULT)

set(HAVE_GEOIPV6 NO)

if(GEOIPV6_RUN_RESULT EQUAL 1)
  set(HAVE_GEOIPV6 YES)
  message(STATUS "System has GeoIPv6 support")
else(GEOIPV6_RUN_RESULT EQUAL 1)
  message(STATUS "System has no GeoIPv6 (>=1.4.8) support")
endif(GEOIPV6_RUN_RESULT EQUAL 1)
