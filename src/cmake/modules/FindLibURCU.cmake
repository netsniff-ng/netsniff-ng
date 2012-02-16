#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2012 Emmanuel Roullit.
# Subject to the GPL, version 2.
#

# - Find Userspace Read-Copy-Update library
# Find liburcu includes and library.
# Once done this will define
#
#  LIBURCU_INCLUDE_DIR    - where to find header files, etc.
#  LIBURCU_LIBRARY        - List of LIBURCU libraries.
#  LIBURCU_FOUND          - True if liburcu is found.
#

FIND_PATH(LIBURCU_ROOT_DIR
    NAMES include/urcu.h
)

SET(LIBURCU_NAME urcu)

FIND_LIBRARY(LIBURCU_LIBRARY
    NAMES ${LIBURCU_NAME}
    HINTS ${LIBURCU_ROOT_DIR}/lib
)

FIND_PATH(LIBURCU_INCLUDE_DIR
    NAMES urcu.h
    HINTS ${LIBURCU_ROOT_DIR}/include
)

# handle the QUIETLY and REQUIRED arguments and set LIBURCU_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(liburcu REQUIRED_VARS
	LIBURCU_LIBRARY
	LIBURCU_INCLUDE_DIR)

MARK_AS_ADVANCED(
	LIBURCU_ROOT_DIR
	LIBURCU_LIBRARY
    	LIBURCU_INCLUDE_DIR
)
