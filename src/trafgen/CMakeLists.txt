PROJECT(trafgen C)

INCLUDE(Pod2Man)

SET(BUILD_STRING "generic")

ADD_EXECUTABLE(${PROJECT_NAME} 	../xmalloc.c
				../xio.c
				../xsys.c
				../xstring.c
				../mtrand.c
				../ring_tx.c
				../trafgen_cli.c
				../trafgen.c)
ADD_DEFINITIONS(-DPROGNAME_STRING="${PROJECT_NAME}"
		-DVERSION_STRING="${VERSION}"
		-DBUILD_STRING="${BUILD_STRING}")
# FIXME
TARGET_LINK_LIBRARIES(trafgen -lcli)
POD2MAN(${CMAKE_SOURCE_DIR}/trafgen.c trafgen 8)
INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${EXECUTABLE_INSTALL_PATH})
