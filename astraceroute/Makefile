astraceroute-libs =	-lpthread

ifeq ($(CONFIG_GEOIP), 1)
astraceroute-libs +=	-lGeoIP \
			-lz
endif


astraceroute-objs =	xmalloc.o \
			ioops.o \
			proto_none.o \
			tprintf.o \
			bpf.o \
			str.o \
			sig.o \
			sock.o \
			link.o \
			dev.o \
			ring_rx.o \
			ring.o \
			astraceroute.o

ifeq ($(CONFIG_GEOIP), 1)
astraceroute-objs +=	geoip.o
endif

astraceroute-eflags =

astraceroute-confs =	geoip.conf
