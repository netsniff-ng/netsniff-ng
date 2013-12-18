flowtop-libs =	-lGeoIP \
		-lurcu \
		-lnetfilter_conntrack \
		$(shell pkg-config --libs ncurses 2> /dev/null \
			|| echo '-lncurses') \
		$(shell pkg-config --libs tinfo 2> /dev/null ) \
		-lpthread \
		-lz

flowtop-objs =	xmalloc.o \
		ioops.o \
		oui.o \
		str.o \
		sig.o \
		sock.o \
		dev.o \
		link.o \
		hash.o \
		dissector_eth.o \
		dissector_80211.o \
		dissector.o \
		proto_none.o \
		tprintf.o \
		geoip.o \
		screen.o \
		flowtop.o

flowtop-eflags = $(shell pkg-config --cflags ncurses)

flowtop-confs =	tcp.conf \
		udp.conf \
		geoip.conf
