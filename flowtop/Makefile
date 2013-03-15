flowtop-libs =	-lGeoIP \
		-lurcu \
		-lnetfilter_conntrack \
		$(shell pkg-config --libs ncurses) \
		-lpthread \
		-lz

flowtop-objs =	xmalloc.o \
		xio.o \
		xutils.o \
		oui.o \
		hash.o \
		dissector_eth.o \
		dissector_80211.o \
		dissector.o \
		proto_none.o \
		tprintf.o \
		geoip.o \
		flowtop.o
