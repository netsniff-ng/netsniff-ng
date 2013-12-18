ifpps-libs =	$(shell pkg-config --libs ncurses 2> /dev/null \
			|| echo '-lncurses') \
		$(shell pkg-config --libs tinfo 2> /dev/null )

ifpps-objs =	xmalloc.o \
		ioops.o \
		str.o \
		link.o \
		sock.o \
		dev.o \
		sig.o \
		screen.o \
		ifpps.o

ifpps-eflags = $(shell pkg-config --cflags ncurses 2> /dev/null)

ifpps-confs =
