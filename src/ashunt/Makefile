#
# Makefile for ashunt
# Author: Daniel Borkmann
#

include ../definitions.mk

INCLUDE    = -I..
CFLAGS    +=
LIBS       =

core-objs  = ashunt.o
lib-objs   = xmalloc.o                  \
	     aslookup.o                 \
	     parser.o                   \
	     strlcpy.o

target     = ashunt

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
#	@cd ../../Documentation && make ifpps
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
	@install -d $(DESTDIR)/$(ETCDIR)/$(GLOBALCFGDIR)/
	@cp -r ../conf/whois.conf $(DESTDIR)/$(ETCDIR)/$(GLOBALCFGDIR)/
	@install -D $(target).8.gz $(DESTDIR)/usr/share/man/man8/$(target).8.gz

uninstall:
	@rm $(DESTDIR)/$(BINDIR)/$(target) || true
	@rm $(DESTDIR)/usr/share/man/man8/$(target).8.gz || true

help:
	@echo 'Cleaning targets:'
	@echo '  clean           - Remove generated files'
	@echo 'Building targets:'
	@echo '  all             - Build ashunt (default)'
	@echo '  debug           - Build ashunt for debugging _only_'
	@echo '  deploy          - Build ashunt for productive use'
	@echo 'Setup targets:'
	@echo '  install         - Install ashunt'
	@echo '  uninstall       - Uninstall ashunt'
	@echo 'Other targets:'
	@echo '  help            - Print this help'

