#Project name is not mandatory, but you should use it
PROJECT(netsniff-ng-toolkit C)

# States that CMake required version must be >= 2.6
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

SET(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
# Activate this when you want to build a shared lib out the the lib/ directory
# Bear in mind that no profiling will be available on 64-bit arch when on
# SET(BUILD_SHARED_LIBS ON)

INCLUDE(CheckBPF)
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

ADD_SUBDIRECTORY(src)
