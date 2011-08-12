#
# Makefile for bpfc
# Author: Daniel Borkmann
#

include ../definitions.mk

INCLUDE    = -I.. -I.
CFLAGS    += 
LIBS       =

core-objs  = bpfc.o
lib-objs   = xmalloc.o                  \
	     bpf.o                      \
	     lex.yy.o                   \
	     bpf_parser.tab.o           \
	     strlcpy.o
flex-obj   = ../bpf_lexer.l
bison-obj  = ../bpf_parser.y

target     = bpfc

all: clean gen-version build doc
debug: all
deploy: all strip

gen-version:
	@cd .. && cat ../VERSION | xargs ./gen_build_info.pl

gen-flex-bison:
	@$(FL) $(flex-obj)
	@$(BI) $(bison-obj)
	@mv bpf_parser.tab.c ../
	@mv bpf_parser.tab.h ../
	@mv lex.yy.c ../

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

../bpf_parser.tab.c: gen-flex-bison
../lex.yy.c: gen-flex-bison

%.o: ../%.c
	@$(CC) -g $(CFLAGS) $(INCLUDE) $<

clean:
	@rm *.o *~ $(target) ../version.h *.gz *.pdf *.html *.8 *.css \
	../bpf_parser.tab.c ../bpf_parser.tab.h ../lex.yy.c > /dev/null 2>&1 || true

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
	@echo '  all             - Build bpfc (default)'
	@echo '  debug           - Build bpfc for debugging _only_'
	@echo '  deploy          - Build bpfc for productive use'
	@echo 'Setup targets:'
	@echo '  install         - Install bpfc'
	@echo '  uninstall       - Uninstall bpfc'
	@echo 'Other targets:'
	@echo '  help            - Print this help'

