#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2011 Emmanuel Roullit.
# Subject to the GPL, version 2.
#

# Find the native NaCl includes and library. This module defines:
#  NACL_FOUND       - whether the libnacl library was found
#  NACL_LIBRARY     - the libnacl library
#  NACL_INCLUDE_DIR - the include path of the libnacl library

set(NACL_NAME libnacl.a)

find_library(
  NACL_LIBRARY
  NAMES ${NACL_NAME}
  HINTS ${NACL_LIB_DIR}
)

mark_as_advanced(
  NACL_LIBRARY
  NACL_INCLUDE_DIR
)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(
  NaCl REQUIRED_VARS
  NACL_LIBRARY
  NACL_INCLUDE_DIR
)
