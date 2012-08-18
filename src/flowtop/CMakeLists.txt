project(flowtop C)

set(BUILD_STRING "generic")

find_package(LibGeoIP)
find_package(Threads)
find_package(Curses)
find_package(LibNetFilterConnTrack)
find_package(LibURCU)
include(Pod2Man)

if(CURSES_FOUND AND CMAKE_HAVE_PTHREAD_CREATE AND LIBGEOIP_FOUND AND
   LIBNETFILTER_CONNTRACK_FOUND AND LIBURCU_FOUND)

  add_executable(
    ${PROJECT_NAME}
    ../xmalloc.c
    ../oui.c
    ../xio.c
    ../xutils.c
    ../hash.c
    ../dissector_eth.c
    ../dissector_80211.c
    ../dissector.c
    ../proto_none.c
    ../tprintf.c
    ../flowtop.c
  )

  add_definitions(
    -DPROGNAME_STRING="${PROJECT_NAME}"
    -DVERSION_STRING="${VERSION}"
    -DBUILD_STRING="${BUILD_STRING}"
  )

  target_link_libraries(
    ${PROJECT_NAME}
    ${CURSES_NCURSES_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${LIBNETFILTER_CONNTRACK_LIBRARY}
    ${LIBGEOIP_LIBRARY}
    ${LIBURCU_LIBRARY}
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
    FILES ../conf/oui.conf ../conf/udp.conf ../conf/tcp.conf ../conf/ether.conf
    DESTINATION ${CONFIG_INSTALL_PATH}
  )
else(CURSES_FOUND AND CMAKE_HAVE_PTHREAD_CREATE AND LIBGEOIP_FOUND AND
     LIBNETFILTER_CONNTRACK_FOUND AND LIBURCU_FOUND)
  if(NOT CURSES_FOUND)
    message("libncurses is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT CURSES_FOUND)

  if(NOT CMAKE_HAVE_PTHREAD_CREATE)
    message("libpthread is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT CMAKE_HAVE_PTHREAD_CREATE)

  if(NOT LIBGEOIP_FOUND)
    message("libgeoip is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT LIBGEOIP_FOUND)

  if(NOT LIBNETFILTER_CONNTRACK_FOUND)
    message("libnetfilter_conntrack is missing on target. "
            "Skipping ${PROJECT_NAME} build.")
  endif(NOT LIBNETFILTER_CONNTRACK_FOUND)

  if(NOT LIBURCU_FOUND)
    message("liburcu is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT LIBURCU_FOUND)
endif(CURSES_FOUND AND CMAKE_HAVE_PTHREAD_CREATE AND LIBGEOIP_FOUND AND
      LIBNETFILTER_CONNTRACK_FOUND AND LIBURCU_FOUND)
