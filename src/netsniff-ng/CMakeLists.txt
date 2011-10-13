PROJECT(netsniff-ng C)

SET(VERSION "0.5.6.0")
SET(BUILD_STRING "generic")

ADD_EXECUTABLE(${PROJECT_NAME} 	../hash.c
				../dissector.c
				../dissector_eth.c
				../xmalloc.c
				../strlcpy.c
				../misc.c
				../bpf.c
				../parser.c
				../psched.c
				../pcap.c
				../tlsf.c
				../rw_pcap.c
				../sg_pcap.c
				../mmap_pcap.c
				../write_or_die.c
				../rx_ring.c
				../tx_ring.c
				../mtrand.c
				../netdev.c
				../tprintf.c
				netsniff-ng.c)

ADD_DEFINITIONS(-DPROGNAME_STRING="${PROJECT_NAME}"
		-DVERSION_STRING="${VERSION}"
		-DBUILD_STRING="${BUILD_STRING}")

TARGET_LINK_LIBRARIES(netsniff-ng ${CMAKE_THREAD_LIBS_INIT})
