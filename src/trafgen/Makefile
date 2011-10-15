#
# Makefile for trafgen
# Author: Daniel Borkmann
#

include ../definitions.mk

INCLUDE    = -I..
CFLAGS    +=
LIBS       = -lpthread -lnuma

core-objs  = trafgen.o
lib-objs   = xmalloc.o                  \
	     strlcpy.o                  \
	     psched.o                   \
	     misc.o                     \
	     parser.o                   \
	     mtrand.o                   \
	     opt_memcpy.o               \
	     write_or_die.o             \
	     tx_ring.o                  \
	     netdev.o

target     = trafgen

all: clean gen-version build doc strip
debug: all
deploy: all strip

gen-version:
	@cd .. && cat ../VERSION | xargs ./gen_build_info.pl

build: $(lib-objs) $(core-objs)
	@$(LD) $(target) $(core-objs) $(lib-objs) $(LIBS)

strip:
	@strip $(target)

doc:
#	@cd ../../Documentation && make clean
#	@cd ../../Documentation && make trafgen
#	@cp ../../Documentation/man/* .
#	@cp ../../Documentation/pdf/* .
#	@cp ../../Documentation/html/* .

%.o: ../%.c
	@$(CC) $(CFLAGS) $(INCLUDE) $<

clean:
	@rm *.o *~ $(target) ../version.h *.gz *.pdf *.html *.8 *.css > \
	/dev/null 2>&1 || true

install:
	@install -D $(target) $(DESTDIR)/$(BINDIR)/$(target)
	@install -D $(target).8.gz $(DESTDIR)/usr/share/man/man8/$(target).8.gz

uninstall:
	@rm $(DESTDIR)/$(BINDIR)/$(target) || true
	@rm $(DESTDIR)/usr/share/man/man8/$(target).8.gz || true

help:
	@echo 'Cleaning targets:'
	@echo '  clean           - Remove generated files'
	@echo 'Building targets:'
	@echo '  all             - Build trafgen (default)'
	@echo '  debug           - Build trafgen for debugging _only_'
	@echo '  deploy          - Build trafgen for productive use'
	@echo 'Setup targets:'
	@echo '  install         - Install trafgen'
	@echo '  uninstall       - Uninstall trafgen'
	@echo 'Other targets:'
	@echo '  help            - Print this help'

