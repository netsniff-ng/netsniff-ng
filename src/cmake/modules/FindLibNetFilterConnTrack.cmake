#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2012 Emmanuel Roullit.
# Subject to the GPL, version 2.
#

# - Find NetFilter Connection Tracking library
# Find the native netfilter_conntrack includes and library.
# Once done this will define
#
#  LIBNETFILTER_CONNTRACK_INCLUDE_DIR    - where to find header files, etc.
#  LIBNETFILTER_CONNTRACK_LIBRARY        - List of libraries when using netfilter_conntrack.
#  LIBNETFILTER_CONNTRACK_FOUND          - True if netfilter_conntrack found.
#

FIND_PATH(LIBNETFILTER_CONNTRACK_ROOT_DIR
    NAMES include/libnetfilter_conntrack/libnetfilter_conntrack.h
)

SET(LIBNETFILTER_CONNTRACK_NAME netfilter_conntrack)

FIND_LIBRARY(LIBNETFILTER_CONNTRACK_LIBRARY
    NAMES ${LIBNETFILTER_CONNTRACK_NAME}
    HINTS ${LIBNETFILTER_CONNTRACK_ROOT_DIR}/lib
)

FIND_PATH(LIBNETFILTER_CONNTRACK_INCLUDE_DIR
    NAMES libnetfilter_conntrack.h
    HINTS ${LIBNETFILTER_CONNTRACK_ROOT_DIR}/include/libnetfilter_conntrack
)

# handle the QUIETLY and REQUIRED arguments and set NETFILTER_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(libnetfilter_conntrack REQUIRED_VARS
    LIBNETFILTER_CONNTRACK_LIBRARY
    LIBNETFILTER_CONNTRACK_INCLUDE_DIR)

MARK_AS_ADVANCED(
    LIBNETFILTER_CONNTRACK_ROOT_DIR
    LIBNETFILTER_CONNTRACK_LIBRARY
    LIBNETFILTER_CONNTRACK_INCLUDE_DIR
)
