include_directories(${CMAKE_SOURCE_DIR})
link_directories(${CMAKE_SOURCE_DIR})

add_executable(
  test_dummy
  test_dummy.c
  tap.c
  ../xutils.c
  ../xmalloc.c
)

add_test(
  Test1
  test_dummy
)
