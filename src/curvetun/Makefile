#
# Makefile for curvetun
# Author: Daniel Borkmann
#

include ../definitions.mk

INCLUDE    = -I..
CFLAGS    += -DTARGETNAME="\"curvetun\""
LIBS       = -lgcrypt -lz -lpthread

core-objs  = curvetun.o
lib-objs   = xmalloc.o                  \
	     strlcpy.o                  \
	     aes256ctr.o                \
	     curves.o                   \
	     ecc.o                      \
	     numtheory.o                \
	     protocol.o                 \
	     serialize.o                \
	     deflate.o                  \
	     stun.o                     \
	     trie.o                     \
	     tlsf.o                     \
	     patricia.o                 \
	     write_or_die.o             \
	     ct_server.o                \
	     ct_client.o                \
	     netdev.o

target     = curvetun

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
#	@cd ../../Documentation && make curvetun
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
	@echo '  all             - Build curvetun (default)'
	@echo '  debug           - Build curvetun for debugging _only_'
	@echo '  deploy          - Build curvetun for productive use'
	@echo 'Setup targets:'
	@echo '  install         - Install curvetun'
	@echo '  uninstall       - Uninstall curvetun'
	@echo 'Other targets:'
	@echo '  help            - Print this help'

