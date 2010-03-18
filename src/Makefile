#
# Makefile for netsniff-ng
#

CC               = echo "CC        $<"; \
		   gcc $(ARGS)
LIBS             = -lpthread -lrt
INCLUDE          = -Iinclude
CFLAGS           = -O2 -fomit-frame-pointer -fno-strict-aliasing -fno-common -fno-delete-null-pointer-checks
CFLAGS		+= -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -Werror-implicit-function-declaration  \
		   -Wno-format-security -Wcomments -Wendif-labels
CFLAGSDBG        = -g -Q -fdump-translation-unit
MAKEFLAGS 	+= --no-print-directory
BUILD_FOLDERS    = lib
NAME             = netsniff-ng
OBJECTS          = netsniff-ng.o
BINDIR           = usr/sbin
ETCDIR           = etc
MANDIR           = usr/share/man/man8
MANDIR_LOCAL     = doc

all: clean netsniff-ng

netsniff-ng: $(OBJECTS)
	@$(CC) -o $(NAME) $(OBJECTS) $(shell find $(BUILD_FOLDERS) -name "*.o") $(LIBS)

%.o: %.c
	@-for d in $(BUILD_FOLDERS); do (cd $$d; $(MAKE) $(MFLAGS) all); done
	@$(CC) -c $(CFLAGS) $(INCLUDE) $<

install:
	@install -D $(NAME) $(DESTDIR)/$(BINDIR)/$(NAME)
	@install -d $(DESTDIR)/$(ETCDIR)/$(NAME)
	@cp -r rules/ $(DESTDIR)/$(ETCDIR)/$(NAME)/
	@cat $(MANDIR_LOCAL)/$(NAME).8 | gzip --best > $(MANDIR_LOCAL)/$(NAME).8.gz
	@install -D $(MANDIR_LOCAL)/$(NAME).8.gz $(DESTDIR)/$(MANDIR)/$(NAME).8.gz

clean:
	@-for d in $(BUILD_FOLDERS); do (cd $$d; $(MAKE) $(MFLAGS) clean); done
	@rm *.o *.tu *.nccout Code.map $(NAME) $(MANDIR_LOCAL)/$(NAME).8.gz 2&>0 0>/dev/null || true

uninstall:
	@rm $(DESTDIR)/$(BINDIR)/$(NAME) || true
	@rm -rf $(DESTDIR)/$(ETCDIR)/$(NAME) || true
	@rm $(DESTDIR)/$(MANDIR)/$(NAME).8.gz || true

indent:
	$(PWD)/indent_code

check: indent
	$(PWD)/code_check

