#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2011 Emmanuel Roullit.
# Subject to the GPL, version 2.
#

# Find libgeoip includes and library. This module defines:
#  LIBGEOIP_FOUND       - whether the libgeoip library was found
#  LIBGEOIP_LIBRARY     - the libgeoip library
#  LIBGEOIP_INCLUDE_DIR - the include path of the libgeoip library

set(LIBGEOIP_LIBRARIES GeoIP)

find_library(
  LIBGEOIP_LIBRARY
  NAMES ${LIBGEOIP_LIBRARIES}
  HINTS ${LIBGEOIP_ROOT_DIR}/lib
)

find_path(
  LIBGEOIP_ROOT_DIR
  NAMES include/GeoIPCity.h
)

find_path(
  LIBGEOIP_INCLUDE_DIR
  NAMES GeoIPCity.h
  HINTS ${LIBGEOIP_ROOT_DIR}/include
)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(
  LibGeoIP DEFAULT_MSG
  LIBGEOIP_LIBRARY
  LIBGEOIP_INCLUDE_DIR
)

mark_as_advanced(
  LIBGEOIP_ROOT_DIR
  LIBGEOIP_LIBRARY
  LIBGEOIP_INCLUDE_DIR
)
