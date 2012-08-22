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

<<<<<<< HEAD
FIND_LIBRARY(LIBNL_LIBRARY nl)

SET(LIBNL_LIBRARIES ${LIBNL_LIBRARY})

FIND_PATH(LIBNL_INCLUDE_DIR
	NAMES netlink.h
	PATH_SUFFIXES netlink
=======
find_library(LIBNL_LIBRARY nl)

set(LIBNL_LIBRARIES ${LIBNL_LIBRARY})

find_path(
  LIBNL_INCLUDE_DIR
  NAMES netlink.h
  PATH_SUFFIXES netlink
>>>>>>> 79a25c629bcf36727809eac999281f33a4f66b8d
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Libnl DEFAULT_MSG
	LIBNL_LIBRARY
	LIBNL_INCLUDE_DIR)

MARK_AS_ADVANCED(
	LIBNL_INCLUDE_DIR
	LIBNL_LIBRARY
)

