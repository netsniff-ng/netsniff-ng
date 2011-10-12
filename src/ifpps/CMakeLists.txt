ADD_EXECUTABLE(ifpps 		../xmalloc.c
				../strlcpy.c
				../misc.c
				../netdev.c
				ifpps.c)
TARGET_LINK_LIBRARIES(ifpps ${CURSES_NCURSES_LIBRARY})
