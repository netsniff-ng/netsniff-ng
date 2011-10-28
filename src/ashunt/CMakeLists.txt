PROJECT(ashunt C)

SET(VERSION "0.1")
SET(BUILD_STRING "generic")

FIND_PACKAGE(LibGeoIP)

IF(LIBGEOIP_FOUND)
	ADD_EXECUTABLE(${PROJECT_NAME}	../xmalloc.c
					../strlcpy.c
					../write_or_die.c
					../misc.c
					../netdev.c
					../aslookup.c
					../bpf.c
					../mtrand.c
					../parser.c
					../rx_ring.c
					ashunt.c)

	ADD_DEFINITIONS(-DPROGNAME_STRING="${PROJECT_NAME}"
			-DVERSION_STRING="${VERSION}"
			-DBUILD_STRING="${BUILD_STRING}")

	TARGET_LINK_LIBRARIES(ashunt ${LibGeoIP_LIBRARY})
ELSE(LIBGEOIP_FOUND)
	MESSAGE("libgeoip is missing on target. Skipping ${PROJECT_NAME} build.")
ENDIF(LIBGEOIP_FOUND)
