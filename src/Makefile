#
# Makefile for netsniff-ng
#

CC               = gcc $(ARGS)
LIBS             = -lpthread -lrt
INCLUDE          = -Iinclude
CFLAGS           = -Wall -O2
CFLAGSDBG        = -fdump-translation-unit

BUILD_FOLDERS    = lib

NAME             = netsniff-ng
OBJECTS          = netsniff-ng.o

BINDIR           = usr/sbin
ETCDIR           = etc
MANDIR           = usr/share/man/man8
MANDIR_LOCAL     = doc

all: clean netsniff-ng

netsniff-ng: $(OBJECTS)
	$(CC) -o $(NAME) $(OBJECTS) $(shell find $(BUILD_FOLDERS) -name "*.o") $(LIBS)

%.o: %.c
	-for d in $(BUILD_FOLDERS); do (cd $$d; $(MAKE) $(MFLAGS) all); done
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

install:
	install -D $(NAME) $(DESTDIR)/$(BINDIR)/$(NAME)
	install -d $(DESTDIR)/$(ETCDIR)/$(NAME)
	cp -r rules/ $(DESTDIR)/$(ETCDIR)/$(NAME)/
	cat $(MANDIR_LOCAL)/$(NAME).8 | gzip --best > $(MANDIR_LOCAL)/$(NAME).8.gz
	install -D $(MANDIR_LOCAL)/$(NAME).8.gz $(DESTDIR)/$(MANDIR)/$(NAME).8.gz

clean:
	-for d in $(BUILD_FOLDERS); do (cd $$d; $(MAKE) $(MFLAGS) clean); done
	rm *.o *.tu *.nccout Code.map $(NAME) $(MANDIR_LOCAL)/$(NAME).8.gz || true

uninstall:
	rm $(DESTDIR)/$(BINDIR)/$(NAME) || true
	rm -rf $(DESTDIR)/$(ETCDIR)/$(NAME) || true
	rm $(DESTDIR)/$(MANDIR)/$(NAME).8.gz || true

indent:
	$(PWD)/indent_code

stats: indent
	$(PWD)/code_stats

