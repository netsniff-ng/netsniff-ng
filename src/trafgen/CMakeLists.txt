project(trafgen C)

set(BUILD_STRING "generic")

find_package(FLEX)
find_package(BISON)
find_package(Libnl)
include(Pod2Man)

if(FLEX_FOUND AND BISON_FOUND AND LIBNL_FOUND)
  flex_target(
    BPF_LEXER ../trafgen_lexer.l
    ${CMAKE_CURRENT_BINARY_DIR}/trafgen_lex.yy.c
  )

  bison_target(
    BPF_PARSER ../trafgen_parser.y
    ${CMAKE_CURRENT_BINARY_DIR}/trafgen_parser.tab.c
  )

  add_executable(
    ${PROJECT_NAME}
    ../xmalloc.c
    ../xio.c
    ../xutils.c
    ../mtrand.c
    ../mac80211.c
    ../ring_tx.c
    ${FLEX_BPF_LEXER_OUTPUTS}
    ${BISON_BPF_PARSER_OUTPUT_SOURCE}
    ../trafgen.c
  )

  add_definitions(
    -DPROGNAME_STRING="${PROJECT_NAME}"
    -DVERSION_STRING="${VERSION}"
    -DBUILD_STRING="${BUILD_STRING}"
  )

  if(HAVE_HWTSTAMP)
    add_definitions(
      -D__WITH_HARDWARE_TIMESTAMPING
    )
  endif(HAVE_HWTSTAMP)

  target_link_libraries(
    ${PROJECT_NAME}
    ${LIBNL_LIBRARIES}
    ${LIBNL_GENL_LIBRARY}
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
    FILES ../../Documentation/Trafgen
    DESTINATION ${DOC_INSTALL_PATH}
  )
else(FLEX_FOUND AND BISON_FOUND AND LIBNL_FOUND)
  if(NOT FLEX_FOUND)
    message("flex is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT FLEX_FOUND)

  if(NOT BISON_FOUND)
    message("bison is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT BISON_FOUND)

  if(NOT LIBNL_FOUND)
    message("libnl is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT LIBNL_FOUND)
endif(FLEX_FOUND AND BISON_FOUND AND LIBNL_FOUND)
