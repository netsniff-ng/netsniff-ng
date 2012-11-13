#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2011 Emmanuel Roullit.
# Subject to the GPL, version 2.
#

# Find libnl includes and library. This module defines:
#  LIBNL_FOUND       - whether the libnl library was found
#  LIBNL_LIBRARIES   - the libnl library
#  LIBNL_INCLUDE_DIR - the include path of the libnl library

find_library(LIBNL_LIBRARY nl-3)
find_library(LIBNL_GENL_LIBRARY nl-genl-3)

message(STATUS LIBNL_LIBRARY=${LIBNL_LIBRARY})
message(STATUS LIBNL_GENL_LIBRARY=${LIBNL_GENL_LIBRARY})

set(LIBNL_LIBRARIES ${LIBNL_LIBRARY})
set(LIBNL_GENL_LIBRARIES ${LIBNL_GENL_LIBRARY})

find_path(
  LIBNL_INCLUDE_DIR
  NAMES netlink/version.h
  PATH_SUFFIXES include/libnl3
)

include_directories(AFTER ${LIBNL_INCLUDE_DIR})
message(STATUS LIBNL_INCLUDE_DIR2=${LIBNL_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(
   Libnl DEFAULT_MSG
   LIBNL_LIBRARY
   LIBNL_INCLUDE_DIR
)

mark_as_advanced(
   LIBNL_INCLUDE_DIR
   LIBNL_LIBRARY
)


