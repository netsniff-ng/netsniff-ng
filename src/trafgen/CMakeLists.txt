PROJECT(trafgen C)

SET(BUILD_STRING "generic")

ADD_EXECUTABLE(${PROJECT_NAME} 	../xmalloc.c
				../xio.c
				../xsys.c
				../xstring.c
				../parser.c
				../mtrand.c
				../opt_memcpy.c
				../ring_tx.c
				../trafgen.c)

ADD_DEFINITIONS(-DPROGNAME_STRING="${PROJECT_NAME}"
		-DVERSION_STRING="${VERSION}"
		-DBUILD_STRING="${BUILD_STRING}")
INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${EXECUTABLE_INSTALL_PATH})
