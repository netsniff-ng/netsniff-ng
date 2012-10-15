project(mausezahn C)

set(BUILD_STRING "generic")

find_package(LibCLI)
find_package(Threads)
include(Pod2Man)

if(LIBCLI_FOUND AND CMAKE_HAVE_PTHREAD_CREATE)
  add_executable(
    ${PROJECT_NAME}
    ../mausezahn.c
    ../layer1.c
    ../layer2.c
    ../layer3.c
    ../layer4.c
    ../hextools.c
    ../tools.c
    ../lookupdev.c
    ../time.c
    ../modifications.c
    ../send_eth.c
    ../send.c
    ../cdp.c 
    ../rtp.c 
    ../dns.c 
    ../rcv_rtp.c
    ../syslog.c
    ../cli.c
    ../cli_cmds.c
    ../cli_launch.c
    ../cli_legacy.c
    ../cli_packet.c
    ../cli_interface.c
    ../cli_set.c
    ../cli_dns.c
    ../cli_arp.c	
    ../cli_bpdu.c
    ../cli_eth.c
    ../cli_ip.c
    ../cli_udp.c
    ../cli_tcp.c
    ../cli_rtp.c
    ../cli_tools.c
    ../tx_switch.c
    ../mops.c
    ../mops_update.c
    ../mops_tools.c
    ../mops_checksums.c
    ../mops_threads.c
    ../mops_dot1Q.c
    ../mops_mpls.c
    ../mops_ip.c
    ../mops_tcp.c
    ../mops_ext.c
    ../mops_ext_arp.c
    ../mops_ext_bpdu.c
    ../mops_ext_rtp.c
    ../parse_xml.c
    ../automops.c
    ../mopsrx_arp.c
    ../mops_ext_igmp.c
    ../mops_ext_lldp.c
    ../cli_igmp.c
    ../cli_lldp.c
    ../cli_sequence.c
    ../mops_sequence.c
    ../llist.c
    ../directmops.c
    ../xutils.c
  )

  add_definitions(
    -DPROGNAME_STRING="${PROJECT_NAME}"
    -DVERSION_STRING="${VERSION}"
    -DBUILD_STRING="${BUILD_STRING}"
  )

  target_link_libraries(
    ${PROJECT_NAME}
    ${LIBCLI_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    -lnet -lpcap -lrt -lm
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
    FILES ../../Documentation/Mausezahn
    DESTINATION ${DOC_INSTALL_PATH}
  )
else(LIBCLI_FOUND AND CMAKE_HAVE_PTHREAD_CREATE)
  if(NOT LIBCLI_FOUND)
    message("libcli is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT LIBCLI_FOUND)
endif(LIBCLI_FOUND AND CMAKE_HAVE_PTHREAD_CREATE)
