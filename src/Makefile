#
# Makefile for netsniff-ng
#

include .config

INCLUDE    = -Iinclude

core-objs  = netsniff-ng.o
dep-objs   = lib/

target     = netsniff-ng

all: clean netsniff-ng

netsniff-ng: $(core-objs)
	@$(CC) -o $(target) $(core-objs) $(shell find $(dep-objs) -name "*.o") $(LIBS)

%.o: %.c
	@-for d in $(dep-objs); do (cd $$d; $(MAKE) $(MFLAGS) all); done
	@$(CC) -c $(CFLAGS) $(INCLUDE) $<

install:
	@install -D $(target) $(DESTDIR)/$(BINDIR)/$(target)
	@install -d $(DESTDIR)/$(ETCDIR)/$(target)
	@cp -r rules/ $(DESTDIR)/$(ETCDIR)/$(target)/
	@cat $(MANDIR_LOCAL)/$(target).8 | gzip --best > $(MANDIR_LOCAL)/$(target).8.gz
	@install -D $(MANDIR_LOCAL)/$(target).8.gz $(DESTDIR)/$(MANDIR)/$(target).8.gz

clean:
	@-for d in $(dep-objs); do (cd $$d; $(MAKE) $(MFLAGS) clean); done
	@rm *.o *.tu *.nccout *~ Code.map $(target) $(MANDIR_LOCAL)/$(target).8.gz > /dev/null 2>&1 || true

uninstall:
	@rm $(DESTDIR)/$(BINDIR)/$(target) || true
	@rm -rf $(DESTDIR)/$(ETCDIR)/$(target) || true
	@rm $(DESTDIR)/$(MANDIR)/$(target).8.gz || true

indent:
	$(PWD)/scripts/indent_code .

check: indent
	$(PWD)/scripts/code_check .

