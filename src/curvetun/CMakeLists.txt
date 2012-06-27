PROJECT(curvetun C)

SET(BUILD_STRING "generic")

INCLUDE(nacl_path.cmake OPTIONAL)

FIND_PACKAGE(Threads)
FIND_PACKAGE(LibNaCl)

IF (NACL_FOUND AND CMAKE_THREAD_LIBS_INIT)
	ADD_EXECUTABLE(${PROJECT_NAME}	../xmalloc.c
					../xio.c
					../xutils.c
					../stun.c
					../mtrand.c
					../patricia.c
					../trie.c
					../hash.c
					../curve.c
					../ct_cpusched.c
					../ct_usermgmt.c
					../ct_servmgmt.c
					../ct_server.c
					../ct_client.c
					../curvetun.c)
	ADD_DEFINITIONS(-DPROGNAME_STRING="${PROJECT_NAME}"
			-DVERSION_STRING="${VERSION}"
			-DBUILD_STRING="${BUILD_STRING}")
	INCLUDE_DIRECTORIES(${NACL_INCLUDE_DIR})
	TARGET_LINK_LIBRARIES(curvetun ${NACL_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
	POD2MAN(${CMAKE_SOURCE_DIR}/curvetun.c curvetun 8)
	INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${EXECUTABLE_INSTALL_PATH})
ELSE (NACL_FOUND AND CMAKE_THREAD_LIBS_INIT)
	MESSAGE("NaCl was not found. Check if NACL_INCLUDE_DIR and NACL_LIB_DIR are properly set in nacl_path.cmake. Skipping ${PROJECT_NAME} build")
ENDIF (NACL_FOUND AND CMAKE_THREAD_LIBS_INIT)
