project(netsniff-ng-suite C)

cmake_minimum_required(VERSION 2.6)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
set(EXECUTABLE_INSTALL_PATH /usr/sbin)
set(CONFIG_INSTALL_PATH /etc/netsniff-ng)
set(DOC_INSTALL_PATH share/doc/netsniff-ng)

set(VERSION "0.5.8")

include(CheckBPFAttach)
include(CheckPFPacket)
include(CheckStrictAlign)
include(CheckTxRing)
include(CheckHwTimestamp)
include(CheckGeoIpv6)

include(Pod2Man)

add_definitions(
  -O3
  -fstack-protector
  --param=ssp-buffer-size=4
  -fpie
  -std=gnu99
  -fno-strict-aliasing
  -fexceptions
  -fasynchronous-unwind-tables
  -fno-delete-null-pointer-checks
  -D_FORTIFY_SOURCE=2
  -D_REENTRANT
  -march=native
  -mtune=native
  -Wall
  -Wmissing-prototypes
#  -Wstrict-prototypes
  -Wdeclaration-after-statement
  -Werror-implicit-function-declaration
  -Wundef
  -Wformat=2
#  -Wframe-larger-than=2048
)

if(CMAKE_BUILD_TYPE STREQUAL pedantic)
  add_definitions(
    -Wextra
    -Werror
  )
endif(CMAKE_BUILD_TYPE STREQUAL pedantic)

if(CMAKE_BUILD_TYPE STREQUAL profile)
  add_definitions(
    -g
    -pg
    -gnato
    -fmudflap
    -fstack-check
  )
endif(CMAKE_BUILD_TYPE STREQUAL profile)

enable_testing()

add_manpage_target()

include_directories(.)

add_subdirectory(netsniff-ng)
add_subdirectory(trafgen)
add_subdirectory(mausezahn)
add_subdirectory(bpfc)
add_subdirectory(ifpps)
add_subdirectory(flowtop)
add_subdirectory(astraceroute)
add_subdirectory(curvetun)

install(
  FILES ../Documentation/RelNotes/Notes-0.5.6
        ../Documentation/RelNotes/Notes-0.5.7
  DESTINATION ${DOC_INSTALL_PATH}
)

install(
  FILES ../Documentation/IPv6Notes
        ../Documentation/KnownIssues
        ../Documentation/Performance
        ../Documentation/RelatedWork
        ../Documentation/Sponsors
        ../Documentation/Summary
        ../Documentation/SubmittingPatches
        ../Documentation/CodingStyle
        ../Documentation/Maintainer
        ../Documentation/VendorWishlist
        ../Documentation/Motivation
        ../Documentation/Mirrors
        ../Documentation/BigPicture.pdf
        ../Documentation/logo.png
  DESTINATION ${DOC_INSTALL_PATH}
)
