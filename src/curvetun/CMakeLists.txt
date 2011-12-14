PROJECT(curvetun C)

SET(VERSION "0.1")
SET(BUILD_STRING "generic")

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

TARGET_LINK_LIBRARIES(curvetun ${CMAKE_THREAD_LIBS_INIT})
