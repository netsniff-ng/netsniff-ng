PROJECT(curvetun C)

SET(BUILD_STRING "generic")

FIND_PACKAGE(Threads)

IF (LIBNACL_LIB_PATH AND LIBNACL_INCLUDE_PATH AND CMAKE_THREAD_LIBS_INIT)

	ADD_EXECUTABLE(${PROJECT_NAME}	../xmalloc.c
					../strlcpy.c
					../write_or_die.c
					../cpusched.c
					../netdev.c
					../stun.c
					../mtrand.c
					../usermgmt.c
					../servmgmt.c
					../trie.c
					../hash.c
					../ct_server.c
					../ct_client.c
					../curvetun.c)

	ADD_DEFINITIONS(-DPROGNAME_STRING="${PROJECT_NAME}"
			-DVERSION_STRING="${VERSION}"
			-DBUILD_STRING="${BUILD_STRING}")

	INCLUDE_DIRECTORIES(${LIBNACL_INCLUDE_PATH})
	TARGET_LINK_LIBRARIES(curvetun ${LIBNACL_LIB_PATH}/libnacl.a ${CMAKE_THREAD_LIBS_INIT})
	INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${EXECUTABLE_INSTALL_PATH})

ELSE (LIBNACL_LIB_PATH AND LIBNACL_INCLUDE_PATH AND CMAKE_THREAD_LIBS_INIT)
	MESSAGE("either there is no libnacl lib/include path or libpthread is missing. Skipping ${PROJECT_NAME} build. Refer to INSTALL for more info")
ENDIF (LIBNACL_LIB_PATH AND LIBNACL_INCLUDE_PATH AND CMAKE_THREAD_LIBS_INIT)
