project(ifpps C)

set(BUILD_STRING "generic")

find_package(Curses)
include(Pod2Man)

if(CURSES_FOUND)
  add_executable(
    ${PROJECT_NAME}
    ../xmalloc.c
    ../xio.c
    ../xutils.c
    ../ifpps.c
  )

  add_definitions(
    -DPROGNAME_STRING="${PROJECT_NAME}"
    -DVERSION_STRING="${VERSION}"
    -DBUILD_STRING="${BUILD_STRING}"
  )

  target_link_libraries(
    ${PROJECT_NAME}
    ${CURSES_NCURSES_LIBRARY}
  )

  pod2man(
    ${CMAKE_SOURCE_DIR}/../Documentation/Manpages/${PROJECT_NAME}.8
    ${PROJECT_NAME} 8
  )

  install(
    TARGETS ${PROJECT_NAME}
    DESTINATION ${EXECUTABLE_INSTALL_PATH}
  )
else(CURSES_FOUND)
  message("libncurses is missing on target. Skipping ${PROJECT_NAME} build.")
endif(CURSES_FOUND)
