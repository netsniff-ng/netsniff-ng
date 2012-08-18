project(curvetun C)

set(BUILD_STRING "generic")

find_package(Threads)
find_package(LibNaCl)
include(nacl_path.cmake OPTIONAL)
include(Pod2Man)

if(NACL_FOUND AND CMAKE_THREAD_LIBS_INIT)
  add_executable(
    ${PROJECT_NAME}
    ../xmalloc.c
    ../xio.c
    ../xutils.c
    ../stun.c
    ../mtrand.c
    ../patricia.c
    ../trie.c
    ../hash.c
    ../curve.c
    ../ct_cpusched.c
    ../ct_usermgmt.c
    ../ct_servmgmt.c
    ../ct_server.c
    ../ct_client.c
    ../curvetun.c
  )

  add_definitions(
    -DPROGNAME_STRING="${PROJECT_NAME}"
    -DVERSION_STRING="${VERSION}"
    -DBUILD_STRING="${BUILD_STRING}"
  )

  include_directories(
    ${NACL_INCLUDE_DIR}
  )

  target_link_libraries(
    ${PROJECT_NAME}
    ${NACL_LIBRARY}
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
else(NACL_FOUND AND CMAKE_THREAD_LIBS_INIT)
  if(NOT NACL_FOUND)
    message("NaCl was not found. Check if NACL_INCLUDE_DIR and NACL_LIB_DIR "
            "are properly set in nacl_path.cmake. Skipping ${PROJECT_NAME} "
            "build.")
  endif(NOT NACL_FOUND)

  if(NOT CMAKE_THREAD_LIBS_INIT)
    message("libpthread is missing on target. Skipping ${PROJECT_NAME} build.")
  endif(NOT CMAKE_THREAD_LIBS_INIT)

endif(NACL_FOUND AND CMAKE_THREAD_LIBS_INIT)
