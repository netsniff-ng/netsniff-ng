#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2012 Emmanuel Roullit.
# Subject to the GPL, version 2.
#

# Find libcli includes and library. This module defines:
#  LIBCLI_FOUND       - whether the libcli library was found
#  LIBCLI_LIBRARY     - the libcli library
#  LIBCLI_INCLUDE_DIR - the include path of the libcli library

set(LIBCLI_NAME cli)

find_library(
  LIBCLI_LIBRARY
  NAMES ${LIBCLI_NAME}
  HINTS ${LIBCLI_ROOT_DIR}/lib
)

find_path(
  LIBCLI_ROOT_DIR
  NAMES include/libcli.h
)

find_path(
  LIBCLI_INCLUDE_DIR
  NAMES libcli.h
  HINTS ${LIBCLI_ROOT_DIR}/include
)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(
  libcli REQUIRED_VARS
  LIBCLI_LIBRARY
  LIBCLI_INCLUDE_DIR
)

mark_as_advanced(
  LIBCLI_ROOT_DIR
  LIBCLI_LIBRARY
  LIBCLI_INCLUDE_DIR
)
