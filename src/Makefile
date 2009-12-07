#
# Makefile for netsniff-ng
#

CC               = gcc
LIBS             = -lpthread
INCLUDE          = -Iinclude
CFLAGS           = -Wall -O2

NAME_NETSNIFF    = netsniff-ng
OBJECTS_NETSNIFF = netsniff-ng.o

NAME_CHECKP      = check_packets
OBJECTS_CHECKP   = check_packets.o

BINDIR           = usr/bin
ETCDIR           = etc
MANDIR           = usr/share/man/man8
MANDIR_LOCAL     = doc

all: check_packets netsniff-ng

check_packets: $(OBJECTS_CHECKP)
	$(CC) -o $(NAME_CHECKP) $(OBJECTS_CHECKP) $(LIBS)

netsniff-ng: $(OBJECTS_NETSNIFF)
	$(CC) -o $(NAME_NETSNIFF) $(OBJECTS_NETSNIFF) $(LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

install:
	install -D $(NAME_NETSNIFF) $(DESTDIR)/$(BINDIR)/$(NAME_NETSNIFF)
	install -D $(NAME_CHECKP) $(DESTDIR)/$(BINDIR)/$(NAME_CHECKP)
	install -d $(DESTDIR)/$(ETCDIR)/$(NAME_NETSNIFF)
	cp -r rules/ $(DESTDIR)/$(ETCDIR)/$(NAME_NETSNIFF)
	cat $(MANDIR_LOCAL)/$(NAME_NETSNIFF).8 | gzip > $(MANDIR_LOCAL)/$(NAME_NETSNIFF).8.gz
	install -D $(MANDIR_LOCAL)/$(NAME_NETSNIFF).8.gz $(DESTDIR)/$(MANDIR)/$(NAME_NETSNIFF).8.gz

clean:
	rm *.o $(NAME_NETSNIFF) $(NAME_CHECKP) $(MANDIR_LOCAL)/$(NAME_NETSNIFF).8.gz || true

uninstall:
	rm $(DESTDIR)/$(BINDIR)/$(NAME_NETSNIFF) || true
	rm $(DESTDIR)/$(BINDIR)/$(NAME_CHECKP) || true
	rm -rf $(DESTDIR)/$(ETCDIR)/$(NAME_NETSNIFF) || true
	rm $(DESTDIR)/$(MANDIR)/$(NAME_NETSNIFF).8.gz || true

