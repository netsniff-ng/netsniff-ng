#
# netsniff-ng - the packet sniffing beast
# By Emmanuel Roullit <emmanuel@netsniff-ng.org>
# Copyright 2009, 2011 Emmanuel Roullit.
# Subject to the GPL, version 2.
#

# - Find NaCl
# Find the native NaCl includes and library.
# Once done this will define
#
#  NACL_INCLUDE_DIR    - where to find NaCL header files, etc.
#  NACL_LIBRARY        - List of libraries when using NaCL.
#  NACL_FOUND          - True if NaCL found.
#

SET(NACL_NAME libnacl.a)
FIND_LIBRARY(NACL_LIBRARY NAMES ${NACL_NAME} HINTS ${NACL_LIB_DIR})
MARK_AS_ADVANCED(NACL_LIBRARY NACL_INCLUDE_DIR)

# handle the QUIETLY and REQUIRED arguments and set NACL_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(NaCl REQUIRED_VARS NACL_LIBRARY NACL_INCLUDE_DIR)

