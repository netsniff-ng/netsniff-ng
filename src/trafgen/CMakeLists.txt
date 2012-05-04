PROJECT(trafgen C)

INCLUDE(Pod2Man)
FIND_PACKAGE(LibCLI)

SET(BUILD_STRING "generic")

IF(LIBCLI_FOUND)
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
	
	TARGET_LINK_LIBRARIES(trafgen ${LIBCLI_LIBRARY})
	POD2MAN(${CMAKE_SOURCE_DIR}/trafgen.c trafgen 8)
	INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${EXECUTABLE_INSTALL_PATH})
ELSE(LIBCLI_FOUND)
	MESSAGE("libcli-dev is missing on target. Skipping ${PROJECT_NAME} build.")
ENDIF(LIBCLI_FOUND)
