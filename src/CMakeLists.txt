PROJECT(netsniff-ng-toolkit C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

SET(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
SET(EXECUTABLE_INSTALL_PATH /usr/sbin)
SET(CONFIG_INSTALL_PATH /etc/netsniff-ng)

SET(VERSION "0.5.6")

INCLUDE(CheckBPFAttach)
INCLUDE(CheckPFPacket)
INCLUDE(CheckStrictAlign)
INCLUDE(CheckTxRing)

ADD_DEFINITIONS(
	-O3
	-fstack-protector
	-fpie
	-std=gnu99
	-fno-strict-aliasing
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
	-Wlong-long
	-Wdisabled-optimization
	-Wstack-protector
	-Waggregate-return
	-Wcast-align
	-Wcast-qual
	-Wunsafe-loop-optimizations
	-Wfloat-equal
	-Wunknown-pragmas
	-Wunused-function
)

IF (CMAKE_BUILD_TYPE STREQUAL profile)
	ADD_DEFINITIONS(-g -pg)
ENDIF (CMAKE_BUILD_TYPE STREQUAL profile)

ENABLE_TESTING()

INCLUDE_DIRECTORIES(.)

ADD_SUBDIRECTORY(netsniff-ng)
ADD_SUBDIRECTORY(ifpps)
ADD_SUBDIRECTORY(trafgen)
ADD_SUBDIRECTORY(bpfc)
ADD_SUBDIRECTORY(ashunt)
ADD_SUBDIRECTORY(curvetun)
ADD_SUBDIRECTORY(flowtop)
ADD_SUBDIRECTORY(warp)
