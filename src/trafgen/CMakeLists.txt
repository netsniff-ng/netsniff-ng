PROJECT(trafgen C)

SET(BUILD_STRING "generic")

ADD_EXECUTABLE(${PROJECT_NAME} 	../xmalloc.c
				../xio.c
				../xsys.c
				../xstring.c
				../mtrand.c
				../opt_memcpy.c
				../ring_tx.c
				../trafgen.c)
ADD_DEFINITIONS(-DPROGNAME_STRING="${PROJECT_NAME}"
		-DVERSION_STRING="${VERSION}"
		-DBUILD_STRING="${BUILD_STRING}")
ADD_CUSTOM_COMMAND(
	SOURCE ../../trafgen.c
	COMMAND pod2man
	ARGS -s 8 ../../trafgen.c ${CMAKE_CURRENT_BINARY_DIR}/trafgen.8
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/trafgen.8
)
ADD_CUSTOM_TARGET(trafgen.8 ALL
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/trafgen.8
)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/trafgen.8 DESTINATION share/man/man8)
INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${EXECUTABLE_INSTALL_PATH})
