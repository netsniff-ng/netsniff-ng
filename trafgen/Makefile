trafgen-libs =	$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --libs libnl-3.0) \
		$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --libs libnl-genl-3.0) \
		-lm

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
		mac80211.o \
		ring_tx.o \
		ring.o \
		timer.o \
		sysctl.o \
		trafgen_lexer.yy.o \
		trafgen_parser.tab.o \
		trafgen.o

trafgen-lex =	trafgen_lexer.yy.o

trafgen-yaac =	trafgen_parser.tab.o

trafgen-eflags = $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --cflags libnl-3.0) \
		 $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --cflags libnl-genl-3.0) \
		 -I..

trafgen-confs =	trafgen_stddef.h

trafgen_post_install:
	$(Q)mv $(DESTDIR)$(ETCDIRE)/trafgen_stddef.h $(DESTDIR)$(ETCDIRE)/stddef.h

trafgen_clean_custom:
	$(Q)$(call RM,$(BUILD_DIR)/*.h $(BUILD_DIR)/*.c)
