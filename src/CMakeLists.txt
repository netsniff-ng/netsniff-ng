project(netsniff-ng-suite C)

cmake_minimum_required(VERSION 2.6)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
set(EXECUTABLE_INSTALL_PATH /usr/sbin)
set(CONFIG_INSTALL_PATH /etc/netsniff-ng)

set(VERSION "0.5.8")

include(CheckBPFAttach)
include(CheckPFPacket)
include(CheckStrictAlign)
include(CheckTxRing)
include(CheckHwTimestamp)
include(Pod2Man)

add_definitions(
  -O3
  -fstack-protector
  -fpie
  -std=gnu99
  -fno-strict-aliasing
  -D_FORTIFY_SOURCE=2
  -D_REENTRANT
  -march=native
  -mtune=native
  -Wall
  -Wundef
  -Wstrict-prototypes
  -Werror-implicit-function-declaration
  -Wformat=2
  -Wcomments
  -Wendif-labels
  -Wuninitialized
  -Winit-self
  -Wstrict-overflow=1
  -Wtype-limits
  -Wmissing-parameter-type
  -Wclobbered
  -Wempty-body
  -Wignored-qualifiers
  -Wmissing-include-dirs
  -Woverlength-strings
  -Wmissing-field-initializers
  -Wmissing-declarations
  -Wmissing-prototypes
  -Wlogical-op
  -Woverride-init
  -Wnested-externs
  -Wredundant-decls
  -Winvalid-pch
  -Wdisabled-optimization
  -Wstack-protector
  -Waggregate-return
  -Wcast-align
  -Wunsafe-loop-optimizations
  -Wfloat-equal
  -Wunknown-pragmas
  -Wunused-function
)

if(CMAKE_BUILD_TYPE STREQUAL profile)
  add_definitions(
    -g
    -pg
  )
endif(CMAKE_BUILD_TYPE STREQUAL profile)

enable_testing()

add_manpage_target()

include_directories(.)

add_subdirectory(netsniff-ng)
add_subdirectory(ifpps)
add_subdirectory(trafgen)
add_subdirectory(bpfc)
add_subdirectory(gremlin)
add_subdirectory(astraceroute)
add_subdirectory(curvetun)
add_subdirectory(flowtop)
