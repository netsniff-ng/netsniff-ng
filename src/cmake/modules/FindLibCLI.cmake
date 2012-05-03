#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2012 Emmanuel Roullit.
# Subject to the GPL, version 2.
#

# - Find CLI library
# Find libcli includes and library.
# Once done this will define
#
#  LIBCLI_INCLUDE_DIR    - where to find header files, etc.
#  LIBCLI_LIBRARY        - List of libcli libraries.
#  LIBCLI_FOUND          - True if libcli is found.
#

FIND_PATH(LIBCLI_ROOT_DIR
    NAMES include/libcli.h
)

SET(LIBCLI_NAME cli)

FIND_LIBRARY(LIBCLI_LIBRARY
    NAMES ${LIBCLI_NAME}
    HINTS ${LIBCLI_ROOT_DIR}/lib
)

FIND_PATH(LIBCLI_INCLUDE_DIR
    NAMES libcli.h
    HINTS ${LIBCLI_ROOT_DIR}/include
)

# handle the QUIETLY and REQUIRED arguments and set LIBCLI_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(libcli REQUIRED_VARS
	LIBCLI_LIBRARY
	LIBCLI_INCLUDE_DIR)

MARK_AS_ADVANCED(
	LIBCLI_ROOT_DIR
	LIBCLI_LIBRARY
	LIBCLI_INCLUDE_DIR
)
