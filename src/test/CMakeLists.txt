INCLUDE_DIRECTORIES (${CMAKE_SOURCE_DIR})
LINK_DIRECTORIES (${CMAKE_SOURCE_DIR})

ADD_EXECUTABLE(test_dummy test_dummy.c tap.c ../xutils.c ../xmalloc.c)
ADD_TEST(Test1 test_dummy)
