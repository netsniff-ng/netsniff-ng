#
# Makefile for netsniff-ng client
# Author: Daniel Borkmann
#

include ../definitions.mk

INCLUDE    = -I..
CFLAGS    += -DTARGETNAME="\"netsniff-ng\""
LIBS       = -lpthread

core-objs  = netsniff-ng.o
lib-objs   = hash.o                  \
	     dissector.o             \
	     dissector_eth.o         \
	     xmalloc.o               \
	     strlcpy.o               \
	     bpf.o                   \
	     parser.o                \
	     psched.o                \
	     misc.o                  \
	     pcap.o                  \
	     tlsf.o                  \
	     rw_pcap.o               \
	     mmap_pcap.o             \
	     sg_pcap.o               \
	     write_or_die.o          \
	     rx_ring.o               \
	     tx_ring.o               \
	     mtrand.o                \
	     netdev.o                \
	     tprintf.o

target     = netsniff-ng

all: clean gen-version build post-build doc strip
debug: all
deploy: all strip

gen-version:
	@cd .. && cat ../VERSION | xargs ./gen_build_info.pl

build: $(lib-objs) $(core-objs)
	@$(LD) $(target) $(core-objs) $(lib-objs) $(LIBS)

post-build:
	@if [ ! -f /etc/netsniff-ng/oui.conf ] ; then echo "NOTE: You need " \
	"to install /etc/netsniff-ng/* files before running, so do a 'make " \
	"install'!"; fi

strip:
	@strip $(target)

doc:
#	@cd ../../Documentation && make clean
#	@cd ../../Documentation && make netsniff-ng
#	@cp ../../Documentation/man/* .
#	@cp ../../Documentation/pdf/* .
#	@cp ../../Documentation/html/* .

%.o: ../%.c
	@$(CC) $(CFLAGS) $(INCLUDE) $<

clean:
	@rm *.o *~ $(target) ../version.h ../twofish_tables.h *.gz *.pdf \
	*.html *.8 *.css > /dev/null 2>&1 || true

install:
	@install -D $(target) $(DESTDIR)/$(BINDIR)/$(target)
	@install -d $(DESTDIR)/$(ETCDIR)/$(target)/rules
	@cp -r ../rules/*.bpf $(DESTDIR)/$(ETCDIR)/$(target)/rules/
	@cp -r ../conf/* $(DESTDIR)/$(ETCDIR)/$(target)/
	@install -D $(target).8.gz $(DESTDIR)/usr/share/man/man8/$(target).8.gz

uninstall:
	@rm $(DESTDIR)/$(BINDIR)/$(target) || true
	@rm $(DESTDIR)/usr/share/man/man8/$(target).8.gz || true

help:
	@echo 'Cleaning targets:'
	@echo '  clean           - Remove generated files'
	@echo 'Building targets:'
	@echo '  all             - Build netsniff-ng (default)'
	@echo '  debug           - Build netsniff-ng for debugging _only_'
	@echo '  deploy          - Build netsniff-ng for productive use'
	@echo 'Setup targets:'
	@echo '  install         - Install netsniff-ng'
	@echo '  uninstall       - Uninstall netsniff-ng'
	@echo 'Other targets:'
	@echo '  help            - Print this help'

