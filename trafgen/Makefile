trafgen-libs =	-lm

ifeq ($(CONFIG_LIBNL), 1)
trafgen-libs +=	$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --libs libnl-3.0) \
		$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --libs libnl-genl-3.0)
endif

trafgen-objs =	xmalloc.o \
		die.o \
		ioops.o \
		privs.o \
		proc.o \
		dev.o \
		irq.o \
		link.o \
		str.o \
		sig.o \
		sock.o \
		ring_tx.o \
		ring.o \
		timer.o \
		sysctl.o \
		cpp.o \
		pcap_sg.o \
		pcap_rw.o \
		pcap_mm.o \
		iosched.o \
		trafgen_dev.o \
		trafgen_dump.o \
		trafgen_proto.o \
		trafgen_l2.o \
		trafgen_l3.o \
		trafgen_l4.o \
		trafgen_l7.o \
		trafgen_lexer.yy.o \
		trafgen_parser.tab.o \
		trafgen.o

ifeq ($(CONFIG_LIBNL), 1)
trafgen-objs += mac80211.o
endif

trafgen-lex =	trafgen_lexer.yy.o

trafgen-yacc =	trafgen_parser.tab.o

trafgen-eflags = -I..

ifeq ($(CONFIG_LIBNL), 1)
trafgen-eflags = $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --cflags libnl-3.0) \
		 $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --cflags libnl-genl-3.0)
endif

trafgen-confs =	trafgen_stddef.h

trafgen_post_install:
	$(Q)mv $(DESTDIR)$(ETCDIRE)/trafgen_stddef.h $(DESTDIR)$(ETCDIRE)/stddef.h

trafgen_clean_custom:
	$(Q)$(call RM,$(BUILD_DIR)/*.h $(BUILD_DIR)/*.c)
