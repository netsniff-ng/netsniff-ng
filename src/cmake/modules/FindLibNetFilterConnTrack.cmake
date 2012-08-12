#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2012 Emmanuel Roullit.
# Subject to the GPL, version 2.
#

# Find libnfct includes and library. This module defines:
#  LIBNETFILTER_CONNTRACK_FOUND       - whether the libnfct library was found
#  LIBNETFILTER_CONNTRACK_LIBRARY     - the libnfct library
#  LIBNETFILTER_CONNTRACK_INCLUDE_DIR - the include path of the libnfct library

set(LIBNETFILTER_CONNTRACK_NAME netfilter_conntrack)

find_library(
  LIBNETFILTER_CONNTRACK_LIBRARY
  NAMES ${LIBNETFILTER_CONNTRACK_NAME}
  HINTS ${LIBNETFILTER_CONNTRACK_ROOT_DIR}/lib
)

find_path(
  LIBNETFILTER_CONNTRACK_ROOT_DIR
  NAMES include/libnetfilter_conntrack/libnetfilter_conntrack.h
)

find_path(
  LIBNETFILTER_CONNTRACK_INCLUDE_DIR
  NAMES libnetfilter_conntrack.h
  HINTS ${LIBNETFILTER_CONNTRACK_ROOT_DIR}/include/libnetfilter_conntrack
)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(
  libnetfilter_conntrack REQUIRED_VARS
  LIBNETFILTER_CONNTRACK_LIBRARY
  LIBNETFILTER_CONNTRACK_INCLUDE_DIR
)

mark_as_advanced(
  LIBNETFILTER_CONNTRACK_ROOT_DIR
  LIBNETFILTER_CONNTRACK_LIBRARY
  LIBNETFILTER_CONNTRACK_INCLUDE_DIR
)
