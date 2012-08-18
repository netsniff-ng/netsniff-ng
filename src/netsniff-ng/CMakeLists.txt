project(netsniff-ng C)

set(BUILD_STRING "generic")

find_package(Threads)
find_package(Libnl)
include(Pod2Man)

if(CMAKE_HAVE_PTHREAD_CREATE AND LIBNL_FOUND)
  add_executable(
    ${PROJECT_NAME}
    ../hash.c
    ../dissector.c
    ../dissector_eth.c
    ../dissector_80211.c
    ../proto_arp.c
    ../proto_ethernet.c
    ../proto_icmpv4.c
    ../proto_icmpv6.c
    ../proto_igmp.c
    ../proto_ip_authentication_hdr.c
    ../proto_ip_esp.c
    ../proto_ipv4.c
    ../proto_ipv6.c
    ../proto_ipv6_dest_opts.c
    ../proto_ipv6_fragm.c
    ../proto_ipv6_hop_by_hop.c
    ../proto_ipv6_in_ipv4.c
    ../proto_ipv6_mobility_hdr.c
    ../proto_ipv6_no_nxt_hdr.c
    ../proto_ipv6_routing.c
    ../proto_none.c
    ../proto_tcp.c
    ../proto_udp.c
    ../proto_vlan.c
    ../proto_vlan_q_in_q.c
    ../proto_mpls_unicast.c
    ../proto_80211_mac_hdr.c
    ../xmalloc.c
    ../oui.c
    ../xio.c
    ../xutils.c
    ../bpf.c
    ../mac80211.c
    ../pcap.c
    ../pcap_rw.c
    ../pcap_sg.c
    ../pcap_mmap.c
    ../ring_rx.c
    ../ring_tx.c
    ../mtrand.c
    ../tprintf.c
    ../netsniff-ng.c
  )

  add_definitions(
    -DPROGNAME_STRING="${PROJECT_NAME}"
    -DVERSION_STRING="${VERSION}"
    -DBUILD_STRING="${BUILD_STRING}"
    -D_FILE_OFFSET_BITS=64
    -D_LARGEFILE_SOURCE
    -D_LARGEFILE64_SOURCE
    -D__WITH_PROTOS
  )

  if(HAVE_HWTSTAMP)
    add_definitions(
      -D__WITH_HARDWARE_TIMESTAMPING
    )
  endif(HAVE_HWTSTAMP)

  target_link_libraries(
    ${PROJECT_NAME}
    ${CMAKE_THREAD_LIBS_INIT}
    ${LIBNL_LIBRARIES}
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
    FILES ${rules_files}
    DESTINATION ${CONFIG_INSTALL_PATH}/rules/
  )

  install(
    FILES ../conf/ether.conf ../conf/tcp.conf ../conf/udp.conf ../conf/oui.conf
    DESTINATION ${CONFIG_INSTALL_PATH}
  )

else(CMAKE_HAVE_PTHREAD_CREATE AND LIBNL_FOUND)
  if(NOT CMAKE_HAVE_PTHREAD_CREATE)
    message("libpthread is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT CMAKE_HAVE_PTHREAD_CREATE)

  if(NOT LIBNL_FOUND)
    message("libnl is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT LIBNL_FOUND)
endif(CMAKE_HAVE_PTHREAD_CREATE AND LIBNL_FOUND)
