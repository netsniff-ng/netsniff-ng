flowtop-libs =	-lurcu \
		-lnetfilter_conntrack \
		$(shell pkg-config --libs ncurses 2> /dev/null \
			|| echo '-lncurses') \
		$(shell pkg-config --libs tinfo 2> /dev/null ) \
		-lpthread

ifeq ($(CONFIG_GEOIP), 1)
flowtop-libs +=	-lGeoIP \
		-lz
endif

flowtop-objs =	xmalloc.o \
		ioops.o \
		oui.o \
		str.o \
		sig.o \
		sock.o \
		dev.o \
		link.o \
		hash.o \
		lookup.o \
		tprintf.o \
		screen.o \
		flowtop.o

ifeq ($(CONFIG_GEOIP), 1)
flowtop-objs +=	geoip.o
endif

flowtop-eflags = $(shell pkg-config --cflags ncurses)

flowtop-confs =	tcp.conf \
		udp.conf \
		geoip.conf
