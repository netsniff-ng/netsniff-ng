#
# Makefile for netsniff-ng main
#

include definitions.mk

INCLUDE    = -Iinclude

core-objs  = netsniff-ng.o
lib-objs   = bpf.o misc.o print.o config.o rx_ring.o system.o dump.o hash.o \
	     netdev.o tx_ring.o bootstrap.o replay.o cursor.o xmalloc.o     \
	     strlcpy.o

target     = netsniff-ng

all: clean build
debug: all
develop: all

#-----------------------------------------------------------------------------

build: $(lib-objs) $(core-objs)
	@$(LD) $(target) $(core-objs) $(lib-objs) $(LIBS)

#-----------------------------------------------------------------------------

%.o: %.c
	@$(CC) $(CFLAGS) $(INCLUDE) $<

#-----------------------------------------------------------------------------

clean:
	@rm *.o *.tu *.nccout *~ Code.map $(target) \
	$(MANDIR_LOCAL)/$(target).8.gz > /dev/null 2>&1 || true

#-----------------------------------------------------------------------------

install:
	@install -D $(target) $(DESTDIR)/$(BINDIR)/$(target)
	@install -d $(DESTDIR)/$(ETCDIR)/$(target)/rules
	@cp -r rules/*.bpf $(DESTDIR)/$(ETCDIR)/$(target)/rules/
	@cat $(MANDIR_LOCAL)/$(target).8 | gzip --best > \
	$(MANDIR_LOCAL)/$(target).8.gz
	@install -D $(MANDIR_LOCAL)/$(target).8.gz \
	$(DESTDIR)/$(MANDIR)/$(target).8.gz

uninstall:
	@rm $(DESTDIR)/$(BINDIR)/$(target) || true
	@rm -rf $(DESTDIR)/$(ETCDIR)/$(target) || true
	@rm $(DESTDIR)/$(MANDIR)/$(target).8.gz || true

#-----------------------------------------------------------------------------

indent:
	$(PWD)/../scripts/indent_code .

help:
	@echo 'Cleaning targets:'
	@echo '  clean           - Remove generated files'
	@echo 'Building targets:'
	@echo '  all             - Build netsniff-ng (default)'
	@echo '  debug           - Build netsniff-ng for debugging _only_'
	@echo '  develop         - Build netsniff-ng for developing _only_'
	@echo 'Setup targets:'
	@echo '  install         - Install netsniff-ng'
	@echo '  uninstall       - Uninstall netsniff-ng'
	@echo 'Other targets:'
	@echo '  help            - Print this help'

