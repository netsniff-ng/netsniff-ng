#
# Makefile for netsniff-ng main
#

include definitions.mk

INCLUDE    = -Iinclude

core-objs  = netsniff-ng.o
dep-objs   = lib/

target     = netsniff-ng

all: clean build
profile: all
debug: all
develop: all

#-----------------------------------------------------------------------------

build: $(core-objs)
	@$(LD) $(target) $(core-objs) $(shell find $(dep-objs) -name "*.o") $(LIBS)

#-----------------------------------------------------------------------------

%.o: %.c
	@for d in $(dep-objs); do (cd $$d; $(MAKE) $(MFLAGS) $(MAKECMDGOALS)); done
	@$(CC) $(CFLAGS) $(INCLUDE) $<

#-----------------------------------------------------------------------------

clean:
	@-for d in $(dep-objs); do (cd $$d; $(MAKE) $(MFLAGS) clean); done
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
	@echo '  profile         - Build netsniff-ng for profiling _only_'
	@echo '  debug           - Build netsniff-ng for debugging _only_'
	@echo '  develop         - Build netsniff-ng for developing _only_'
	@echo 'Setup targets:'
	@echo '  install         - Install netsniff-ng'
	@echo '  uninstall       - Uninstall netsniff-ng'
	@echo 'Other targets:'
	@echo '  indent          - Indent source code'
	@echo '  help            - Print this help'

