# netsniff-ng build system, part of netsniff-ng.
# Copyright 2012 Daniel Borkmann <borkmann@gnumaniacs.org>
# Subject to the GNU GPL, version 2.

VERSION = 0
PATCHLEVEL = 5
SUBLEVEL = 8
EXTRAVERSION = -rc0

TOOLS = netsniff-ng trafgen astraceroute flowtop ifpps mausezahn bpfc

#curvetun

# For packaging purposes, prefix can define a different path.
PREFIX ?=

# Disable if you don't want it
CCACHE = ccache

# Location of installation paths.
BINDIR = $(PREFIX)/usr/bin
SBINDIR = $(PREFIX)/usr/sbin
INCDIR = $(PREFIX)/usr/include
ETCDIR = $(PREFIX)/etc
ETCDIRE = $(ETCDIR)/netsniff-ng
DOCDIR = $(PREFIX)/usr/share/doc
DOCDIRE = $(DOCDIR)/netsniff-ng

# Shut up make, helper warnings, parallel compilation!
MAKEFLAGS += --no-print-directory
MAKEFLAGS += -rR
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --jobs=$(shell grep "^processor" /proc/cpuinfo | wc -l)

# For packaging purposes, you might want to disable O3+arch tuning
CFLAGS = -fstack-protector
CFLAGS += --param=ssp-buffer-size=4
CFLAGS += -fpie
CFLAGS += -fno-strict-aliasing
CFLAGS += -fexceptions
CFLAGS += -fasynchronous-unwind-tables
CFLAGS += -fno-delete-null-pointer-checks
CFLAGS += -D_FORTIFY_SOURCE=2
CFLAGS += -D_REENTRANT
CFLAGS += -D_FILE_OFFSET_BITS=64
CFLAGS += -D_LARGEFILE_SOURCE
CFLAGS += -D_LARGEFILE64_SOURCE
CFLAGS += -D__WITH_HARDWARE_TIMESTAMPING
CFLAGS += -DVERSION_STRING=\"$(VERSION_STRING)\"
CFLAGS += -std=gnu99
CFLAGS += -march=native
CFLAGS += -mtune=native
CFLAGS += -O3
CFLAGS += -g

# Should be commented in after the mausezahn mess is cleaned
WFLAGS  = -Wall
#WFLAGS += -Wmissing-prototypes
#WFLAGS += -Wdeclaration-after-statement
#WFLAGS += -Werror-implicit-function-declaration
#WFLAGS += -Wundef
#WFLAGS += -Wstrict-prototypes
#WFLAGS += -Wunused-but-set-variable
#WFLAGS += -Werror
WFLAGS += -Wformat=2

CFLAGS += $(WFLAGS) -I.
CPPFLAGS =
ifeq ("$(origin CROSS_LD_LIBRARY_PATH)", "command line")
  LDFLAGS = -L$(CROSS_LD_LIBRARY_PATH)
else
  LDFLAGS =
endif

ALL_CFLAGS = $(CFLAGS)
ALL_LDFLAGS = $(LDFLAGS)
TARGET_ARCH =
LEX_FLAGS =
YAAC_FLAGS =

LD = @echo -e "  LD\t$@" && $(CCACHE) $(CROSS_COMPILE)gcc
CCNQ = $(CCACHE) $(CROSS_COMPILE)gcc
CC = @echo -e "  CC\t$<" && $(CCNQ)
RM = @echo -e "  EXEC\t$@" && rm
MKDIR = @echo -e "  MKDIR\t$@" && mkdir
STRIP = @echo -e "  STRIP\t$@" && $(CROSS_COMPILE)strip
LEX = @echo -e "  LEX\t$<" && flex
YAAC = @echo -e "  YAAC\t$<" && bison

export VERSION PATCHLEVEL SUBLEVEL EXTRAVERSION
export CROSS_COMPILE LD CC STRIP

VERSION_STRING = $(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)
VERSION_SHORT = $(VERSION).$(PATCHLEVEL).$(SUBLEVEL)

bold = $(shell tput bold)
normal = $(shell tput sgr0)

build_showinfo:
	@echo "$(bold)Building netsniff-ng toolkit ($(VERSION_STRING)) for" \
	      $(shell $(CCNQ) -dumpmachine)":$(normal)"
clean_showinfo:
	@echo "$(bold)Cleaning netsniff-ng toolkit ($(VERSION_STRING)):$(normal)"

%.yy.o: %.l
	$(LEX) -P $(shell perl -wlne 'print $$1 if /lex-func-prefix:\s([a-z]+)/' $<) \
	       -o $(BUILD_DIR)/$(shell basename $< .l).yy.c $(LEX_FLAGS) $<
%.tab.o: %.y
	$(YAAC) -p $(shell perl -wlne 'print $$1 if /yaac-func-prefix:\s([a-z]+)/' $<) \
		-o $(BUILD_DIR)/$(shell basename $< .y).tab.c $(YAAC_FLAGS) -d $<

.PHONY: all toolkit $(TOOLS) clean %_prehook %_distclean %_clean %_install
.FORCE:
.DEFAULT_GOAL := all
.IGNORE: %_clean_custom %_install_custom
.NOTPARALLEL: $(TOOLS)

all: build_showinfo toolkit
toolkit: $(TOOLS)
install: $(foreach tool,$(TOOLS),$(tool)_install)
	install -D ../Documentation/Summary $(DOCDIRE)
	install -D ../Documentation/RelatedWork $(DOCDIRE)
	install -D ../Documentation/Performance $(DOCDIRE)
	install -D ../Documentation/KnownIssues $(DOCDIRE)
	install -D ../Documentation/IPv6Notes $(DOCDIRE)
	install -D ../Documentation/Sponsors $(DOCDIRE)
	install -D ../Documentation/SubmittingPatches $(DOCDIRE)
	install -D ../Documentation/CodingStyle $(DOCDIRE)
	install -D ../Documentation/logo.png $(DOCDIRE)
	install -D ../Documentation/RelNotes/Notes-$(VERSION_SHORT) $(DOCDIRE)
clean mostlyclean: $(foreach tool,$(TOOLS),$(tool)_clean)
realclean distclean clobber: $(foreach tool,$(TOOLS),$(tool)_distclean)

# Tool template
define TOOL_templ
  include $(1)/Makefile
  $(1) $(1)%: BUILD_DIR := $(1)
  $(1)_prehook:
	@echo "$(bold)Building $(1):$(normal)"
  $(1): $(1)_prehook $$($(1)-lex) $$($(1)-yaac) $$(patsubst %.o,$(1)/%.o,$$($(1)-objs)) $$($(1)-libs)
  $(1)_clean: $(1)_clean_custom
	rm -rf $(1)/*.o $(1)/$(1)
  $(1)_install: $(1)_install_custom
	install -D $(1)/$(1) $$(SBINDIR)/$(1)
	install -D ../Documentation/$$(shell echo $(1) | sed 's/\([a-z]\)\(.*\)/\u\1\2/g') $$(DOCDIRE)
  $(1)_distclean:
	rm $$(SBINDIR)/$(1)
  $(1)/%.o: %.c
	$$(CC) $$(ALL_CFLAGS) -o $(1)/$$(shell basename $$< .c).o -c $$<
endef

$(foreach tool,$(TOOLS),$(eval $(call TOOL_templ,$(tool))))

# Target specific flag additions ...
netsniff-ng: ALL_CFLAGS += -I$(INCDIR)/libnl3/ -D__WITH_PROTOS
trafgen: ALL_CFLAGS += -I.. -I$(INCDIR)/libnl3/ -D__WITH_PROTOS
bpfc: ALL_CFLAGS += -I..

netsniff-ng_clean_custom:
astraceroute_clean_custom:
flowtop_clean_custom:
ifpps_clean_custom:
mausezahn_clean_custom:
bpfc_clean_custom:
	rm $(BUILD_DIR)/*.h $(BUILD_DIR)/*.c
curvetun_clean_custom:
trafgen_clean_custom:
	rm $(BUILD_DIR)/*.h $(BUILD_DIR)/*.c

netsniff-ng_install_custom:
	install -D conf/ether.conf $(ETCDIRE)
	install -D conf/tcp.conf $(ETCDIRE)
	install -D conf/udp.conf $(ETCDIRE)
	install -D conf/oui.conf $(ETCDIRE)
astraceroute_install_custom:
flowtop_install_custom:
ifpps_install_custom:
mausezahn_install_custom:
bpfc_install_custom:
curvetun_install_custom:
trafgen_install_custom:

$(TOOLS):
	$(LD) $(ALL_LDFLAGS) -o $@/$@ $@/*.o $($@-libs)
	$(STRIP) $@/$@
