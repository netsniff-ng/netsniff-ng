PROJECT(curvetun C)

SET(BUILD_STRING "generic")

FIND_PACKAGE(Threads)
FIND_PACKAGE(LibNaCl)

IF (NACL_FOUND AND CMAKE_THREAD_LIBS_INIT)

	ADD_EXECUTABLE(${PROJECT_NAME}	../xmalloc.c
					../strlcpy.c
					../write_or_die.c
					../cpusched.c
					../netdev.c
					../stun.c
					../mtrand.c
					../usermgmt.c
					../servmgmt.c
					../patricia.c
					../trie.c
					../hash.c
					../curve.c
					../ct_server.c
					../ct_client.c
					../parser.c
					../curvetun.c)

	ADD_DEFINITIONS(-DPROGNAME_STRING="${PROJECT_NAME}"
			-DVERSION_STRING="${VERSION}"
			-DBUILD_STRING="${BUILD_STRING}")

	INCLUDE_DIRECTORIES(${NACL_INCLUDE_DIR})
	TARGET_LINK_LIBRARIES(curvetun ${NACL_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
	INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${EXECUTABLE_INSTALL_PATH})

ELSE (NACL_FOUND AND CMAKE_THREAD_LIBS_INIT)
	MESSAGE("either there is no libnacl lib/include path or libpthread is missing. Skipping ${PROJECT_NAME} build. Refer to INSTALL for more info")
ENDIF (NACL_FOUND AND CMAKE_THREAD_LIBS_INIT)
