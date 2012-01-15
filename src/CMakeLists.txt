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
	-O2
	-fstack-protector
	-std=gnu99
	-fno-strict-aliasing
	-Wall
	-Wundef
	-Wstrict-prototypes
	-Wno-trigraphs
	-Werror-implicit-function-declaration
	-Wno-format-security
	-Wcomments
	-Wendif-labels
	-Wno-long-long
	-Wuninitialized
	-Wstrict-overflow=1
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
#ADD_SUBDIRECTORY(warp)
