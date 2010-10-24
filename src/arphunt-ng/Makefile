#
# Makefile for arphunt-ng
# Author: Daniel Borkmann
#

include ../definitions.mk

INCLUDE    = -I..
CFLAGS    +=
LIBS       =

core-objs  = arphunt-ng.o
lib-objs   = xmalloc.o                  \
	     strlcpy.o                  \
	     system.o                   \
	     bpf.o                      \
	     hash.o                     \
	     mersenne_twister.o         \
	     write_or_die.o             \
	     netdev.o

target     = arphunt-ng

all: clean gen-version build
debug: all
develop: all

gen-version:
	@cd .. && cat ../VERSION | xargs ./gen_build_info.pl

build: $(lib-objs) $(core-objs)
	@$(LD) $(target) $(core-objs) $(lib-objs) $(LIBS)

doc:
	@cd ../../Documentation && make clean
	@cd ../../Documentation && make arphunt-ng
	@cp ../../Documentation/man/* .
	@cp ../../Documentation/pdf/* .
	@cp ../../Documentation/html/* .

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
	@echo '  all             - Build arphunt-ng (default)'
	@echo '  debug           - Build arphunt-ng for debugging _only_'
	@echo 'Setup targets:'
	@echo '  install         - Install arphunt-ng'
	@echo '  uninstall       - Uninstall arphunt-ng'
	@echo 'Other targets:'
	@echo '  help            - Print this help'

