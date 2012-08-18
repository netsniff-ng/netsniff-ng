project(bpfc C)

set(BUILD_STRING "generic")

find_package(FLEX)
find_package(BISON)
include(Pod2Man)

if(FLEX_FOUND AND BISON_FOUND)
  flex_target(
    BPF_LEXER ../bpf_lexer.l
    ${CMAKE_CURRENT_BINARY_DIR}/bpfc_lex.yy.c
  )

  bison_target(
    BPF_PARSER ../bpf_parser.y
    ${CMAKE_CURRENT_BINARY_DIR}/bpf_parser.tab.c
  )

  add_executable(
    ${PROJECT_NAME}
    ../xmalloc.c
    ../xutils.c
    ../bpf.c
    ${FLEX_BPF_LEXER_OUTPUTS}
    ${BISON_BPF_PARSER_OUTPUT_SOURCE}
    ../bpfc.c
  )

  add_definitions(
    -DPROGNAME_STRING="${PROJECT_NAME}"
    -DVERSION_STRING="${VERSION}"
    -DBUILD_STRING="${BUILD_STRING}"
  )

  pod2man(
    ${CMAKE_SOURCE_DIR}/../Documentation/Manpages/${PROJECT_NAME}.8
    ${PROJECT_NAME} 8
  )

  install(
    TARGETS ${PROJECT_NAME}
    DESTINATION ${EXECUTABLE_INSTALL_PATH}
  )
else(FLEX_FOUND AND BISON_FOUND)
  if(NOT FLEX_FOUND)
    message("flex is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT FLEX_FOUND)

  if(NOT BISON_FOUND)
    message("bison is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT BISON_FOUND)
endif(FLEX_FOUND AND BISON_FOUND)
