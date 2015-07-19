astraceroute-libs =	-lpthread

ifeq ($(CONFIG_GEOIP), 1)
astraceroute-libs +=	-lGeoIP \
			-lz
endif


astraceroute-objs =	xmalloc.o \
			proto_none.o \
			tprintf.o \
			bpf.o \
			str.o \
			sig.o \
			sock.o \
			link.o \
			dev.o \
			ring.o \
			die.o \
			sysctl.o \
			astraceroute.o

ifeq ($(CONFIG_GEOIP), 1)
astraceroute-objs +=	geoip.o \
			ioops.o
endif

astraceroute-eflags =

astraceroute-confs =	geoip.conf
