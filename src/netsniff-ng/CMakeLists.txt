PROJECT(netsniff-ng C)

SET(BUILD_STRING "generic")
FIND_PACKAGE(Threads)
INCLUDE(Pod2Man)

IF (CMAKE_HAVE_PTHREAD_CREATE)
	ADD_EXECUTABLE(${PROJECT_NAME} 	../hash.c
					../dissector.c
					../dissector_eth.c
					../xmalloc.c
					../xio.c
					../xsys.c
					../xstring.c
					../bpf.c
					../pcap.c
					../pcap_rw.c
					../pcap_sg.c
					../pcap_mmap.c
					../ring_rx.c
					../ring_tx.c
					../mtrand.c
					../tprintf.c
					../netsniff-ng.c)
	ADD_DEFINITIONS(-DPROGNAME_STRING="${PROJECT_NAME}"
		-DVERSION_STRING="${VERSION}"
		-DBUILD_STRING="${BUILD_STRING}"
		-D_FILE_OFFSET_BITS=64
		-D_LARGEFILE_SOURCE
		-D_LARGEFILE64_SOURCE)
	POD2MAN(${CMAKE_SOURCE_DIR}/netsniff-ng.c netsniff-ng 8)
	TARGET_LINK_LIBRARIES(netsniff-ng ${CMAKE_THREAD_LIBS_INIT})
#	FILE(GLOB rules_files "../examples/bpfc/*.bpf")
	INSTALL(FILES ${rules_files} DESTINATION ${CONFIG_INSTALL_PATH}/rules/)
	INSTALL(FILES ../conf/ether.conf ../conf/tcp.conf ../conf/udp.conf ../conf/oui.conf DESTINATION ${CONFIG_INSTALL_PATH})
	INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${EXECUTABLE_INSTALL_PATH})
ELSE(CMAKE_HAVE_PTHREAD_CREATE)
	MESSAGE("pthread is missing on target. Skipping ${PROJECT_NAME} build.")
ENDIF(CMAKE_HAVE_PTHREAD_CREATE)

