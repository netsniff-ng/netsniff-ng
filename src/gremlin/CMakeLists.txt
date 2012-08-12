project(gremlin C)

set(BUILD_STRING "generic")

find_package(LibCLI)
include(Pod2Man)

if(LIBCLI_FOUND)
  add_executable(
    ${PROJECT_NAME}
    ../xmalloc.c
    ../xutils.c
    ../gremlin.c
  )

  add_definitions(
    -DPROGNAME_STRING="${PROJECT_NAME}"
    -DVERSION_STRING="${VERSION}"
    -DBUILD_STRING="${BUILD_STRING}"
  )

  pod2man(
    ${CMAKE_SOURCE_DIR}/gremlin.c
    ${PROJECT_NAME} 8
  )

  install(
    TARGETS ${PROJECT_NAME}
    DESTINATION ${EXECUTABLE_INSTALL_PATH}
  )
else(LIBCLI_FOUND)
  message("libcli is missing on target. Skipping ${PROJECT_NAME} build.")
endif(LIBCLI_FOUND)
