ifpps-libs =	$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --libs ncurses 2> /dev/null \
			|| echo '-lncurses') \
		$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --libs tinfo 2> /dev/null )

ifpps-objs =	xmalloc.o \
		ioops.o \
		str.o \
		link.o \
		sock.o \
		dev.o \
		sig.o \
		screen.o \
		die.o \
		sysctl.o \
		ifpps.o

ifpps-eflags = $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --cflags ncurses 2> /dev/null)

ifpps-confs =
