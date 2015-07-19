flowtop-libs =	-lurcu \
		-lnetfilter_conntrack \
		$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --libs ncurses 2> /dev/null \
			|| echo '-lncurses') \
		$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --libs tinfo 2> /dev/null ) \
		-lpthread

ifeq ($(CONFIG_GEOIP), 1)
flowtop-libs +=	-lGeoIP \
		-lz
endif

flowtop-objs =	xmalloc.o \
		oui.o \
		str.o \
		sig.o \
		sock.o \
		proc.o \
		dev.o \
		link.o \
		hash.o \
		lookup.o \
		tprintf.o \
		screen.o \
		die.o \
		sysctl.o \
		flowtop.o

ifeq ($(CONFIG_GEOIP), 1)
flowtop-objs +=	geoip.o \
		ioops.o
endif

flowtop-eflags = $(shell $(PKG_CONFIG) --cflags ncurses)

flowtop-confs =	tcp.conf \
		udp.conf \
		geoip.conf
