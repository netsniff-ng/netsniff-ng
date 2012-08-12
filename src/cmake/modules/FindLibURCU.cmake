#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2012 Emmanuel Roullit.
# Subject to the GPL, version 2.
#

# Find liburcu includes and library. This module defines:
#  LIBURCU_FOUND       - whether the liburcu library was found
#  LIBURCU_LIBRARY     - the liburcu library
#  LIBURCU_INCLUDE_DIR - the include path of the liburcu library

set(LIBURCU_NAME urcu)

find_library(
  LIBURCU_LIBRARY
  NAMES ${LIBURCU_NAME}
  HINTS ${LIBURCU_ROOT_DIR}/lib
)

find_path(
  LIBURCU_ROOT_DIR
  NAMES include/urcu.h
)

find_path(
  LIBURCU_INCLUDE_DIR
  NAMES urcu.h
  HINTS ${LIBURCU_ROOT_DIR}/include
)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(
  liburcu REQUIRED_VARS
  LIBURCU_LIBRARY
  LIBURCU_INCLUDE_DIR
)

mark_as_advanced(
  LIBURCU_ROOT_DIR
  LIBURCU_LIBRARY
  LIBURCU_INCLUDE_DIR
)
