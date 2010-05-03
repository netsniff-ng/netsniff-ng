#
# Makefile for netfire-ng main
#

include definitions.mk

INCLUDE    = -Iinclude

core-objs  = netfire-ng.o
dep-objs   = .

target     = netfire-ng

all: clean build
debug: all

#-----------------------------------------------------------------------------

build: $(core-objs)
	@$(LD) $(target) $(core-objs) $(LIBS)

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
	@cat $(MANDIR_LOCAL)/$(target).8 | gzip --best > \
	$(MANDIR_LOCAL)/$(target).8.gz
	@install -D $(MANDIR_LOCAL)/$(target).8.gz \
	$(DESTDIR)/$(MANDIR)/$(target).8.gz

uninstall:
	@rm $(DESTDIR)/$(BINDIR)/$(target) || true
	@rm $(DESTDIR)/$(MANDIR)/$(target).8.gz || true

#-----------------------------------------------------------------------------

help:
	@echo 'Cleaning targets:'
	@echo '  clean           - Remove generated files'
	@echo 'Building targets:'
	@echo '  all             - Build netfire-ng (default)'
	@echo '  debug           - Build netfire-ng for debugging _only_'
	@echo 'Setup targets:'
	@echo '  install         - Install netfire-ng'
	@echo '  uninstall       - Uninstall netfire-ng'
	@echo 'Other targets:'
	@echo '  help            - Print this help'

