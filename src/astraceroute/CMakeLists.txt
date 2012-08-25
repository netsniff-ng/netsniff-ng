project(astraceroute C)

set(BUILD_STRING "generic")

find_package(LibGeoIP)
find_package(Threads)
include(Pod2Man)

if(LIBGEOIP_FOUND AND CMAKE_HAVE_PTHREAD_CREATE AND HAVE_GEOIPV6)
  add_executable(
    ${PROJECT_NAME}
    ../xmalloc.c
    ../xio.c
    ../xutils.c
    ../proto_none.c
    ../tprintf.c
    ../aslookup.c
    ../bpf.c
    ../mtrand.c
    ../ring_rx.c
    ../astraceroute.c
  )

  add_definitions(
    -DPROGNAME_STRING="${PROJECT_NAME}"
    -DVERSION_STRING="${VERSION}"
    -DBUILD_STRING="${BUILD_STRING}"
  )

  target_link_libraries(
    ${PROJECT_NAME}
    ${LIBGEOIP_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
  )

  pod2man(
    ${CMAKE_SOURCE_DIR}/../Documentation/Manpages/${PROJECT_NAME}.8
    ${PROJECT_NAME} 8
  )

  install(
    TARGETS ${PROJECT_NAME}
    DESTINATION ${EXECUTABLE_INSTALL_PATH}
  )

  install(
    PROGRAMS ../../scripts/astraceroute6
    DESTINATION ${EXECUTABLE_INSTALL_PATH}
  )

  install(
    FILES ../conf/whois.conf
    DESTINATION ${CONFIG_INSTALL_PATH}
  )
else(LIBGEOIP_FOUND AND CMAKE_HAVE_PTHREAD_CREATE AND HAVE_GEOIPV6)
  if(NOT LIBGEOIP_FOUND)
    message("libgeoip is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT LIBGEOIP_FOUND)

  if(NOT HAVE_GEOIPV6)
    message("libgeoip is too old on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT HAVE_GEOIPV6)

  if(NOT CMAKE_HAVE_PTHREAD_CREATE)
    message("libpthread is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT CMAKE_HAVE_PTHREAD_CREATE)
endif(LIBGEOIP_FOUND AND CMAKE_HAVE_PTHREAD_CREATE AND HAVE_GEOIPV6)
