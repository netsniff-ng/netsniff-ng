# netsniff-ng build system, part of netsniff-ng.
# Copyright 2012 Daniel Borkmann <borkmann@gnumaniacs.org>
# Subject to the GNU GPL, version 2.

VERSION = 0
PATCHLEVEL = 5
SUBLEVEL = 8
EXTRAVERSION = -rc0

TOOLS = netsniff-ng trafgen astraceroute flowtop ifpps mausezahn bpfc curvetun

# For packaging purposes, prefix can define a different path.
PREFIX ?=

# Location of installation paths.
BINDIR = $(PREFIX)/usr/bin
SBINDIR = $(PREFIX)/usr/sbin
INCDIR = $(PREFIX)/usr/include
ETCDIR = $(PREFIX)/etc

# Shut up make, helper warnings, parallel compilation!
MAKEFLAGS += --no-print-directory -rR --warn-undefined-variables \
	     --jobs=$(shell grep "^processor" /proc/cpuinfo | wc -l)

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
CFLAGS += -DVERSION_STRING=\"$(VERSION_STRING)\"
CFLAGS += -std=gnu99
CFLAGS += -march=native
CFLAGS += -mtune=native
CFLAGS += -O3
CFLAGS += -g

WFLAGS  = -Wall
#WFLAGS += -Wmissing-prototypes
#WFLAGS += -Wdeclaration-after-statement
#WFLAGS += -Werror-implicit-function-declaration
#WFLAGS += -Wundef
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

LD = @echo -e "  LD\t$@" && $(CROSS_COMPILE)gcc
CCNQ = $(CROSS_COMPILE)gcc
CC = @echo -e "  CC\t$<" && $(CCNQ)
RM = @echo -e "  EXEC\t$@" && rm
MKDIR = @echo -e "  MKDIR\t$@" && mkdir
STRIP = @echo -e "  STRIP\t$@" && $(CROSS_COMPILE)strip
LEX = @echo -e "  LEX\t$<" && flex
YAAC = @echo -e "  YAAC\t$<" && bison

export VERSION PATCHLEVEL SUBLEVEL EXTRAVERSION
export CROSS_COMPILE LD CC STRIP

VERSION_STRING = $(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)

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
%.o: %.c
	$(CC) $(ALL_CFLAGS) -o $(BUILD_DIR)/$(shell basename $< .c).o -c $<

.PHONY: all
.DEFAULT_GOAL := all

all: build_showinfo toolkit
toolkit: $(TOOLS)
clean mostlyclean: $(foreach tool,$(TOOLS),$(tool)_clean)
realclean distclean clobber: $(foreach tool,$(TOOLS),$(tool)_distclean)

define TOOL_templ
  include $(1)/Makefile
  $(1) $(1)%: BUILD_DIR := $(1)
  $(1)_prehook:
	@echo "$(bold)Building $(1):$(normal)"
  $(1): $(1)_prehook $$($(1)-lex) $$($(1)-yaac) $$($(1)-objs) $$($(1)-libs)
  $(1)_clean: $(1)_clean_custom
	@rm -rf $$(BUILD_DIR)/*.o $$(BUILD_DIR)/$(1)
  $(1)_install:
	@install -D $$(BUILD_DIR)/$(1) $$(SBINDIR)/$(1)
  $(1)_distclean:
	@rm $$(SBINDIR)/$(1)
endef

$(foreach tool,$(TOOLS),$(eval $(call TOOL_templ,$(tool))))

# Target specific additions ... will become less redundant when 
# mausezahn is cleaned up

netsniff-ng: ALL_CFLAGS += -I$(INCDIR)/libnl3/ \
			   -Wstrict-prototypes \
			   -D__WITH_PROTOS \
			   #-D__WITH_HARDWARE_TIMESTAMPING
trafgen: ALL_CFLAGS += -I.. -I$(INCDIR)/libnl3/ \
		       -Wstrict-prototypes \
		       -D__WITH_PROTOS \
		       #-D__WITH_HARDWARE_TIMESTAMPING
trafgen_clean_custom:
	@rm $(BUILD_DIR)/*.h $(BUILD_DIR)/*.c
astraceroute: ALL_CFLAGS += -Wstrict-prototypes
flowtop: ALL_CFLAGS += -Wstrict-prototypes
ifpps: ALL_CFLAGS += -Wstrict-prototypes
bpfc: ALL_CFLAGS += -I.. -Wstrict-prototypes
curvetun: ALL_CFLAGS += -Wstrict-prototypes

$(TOOLS):
	$(LD) $(ALL_LDFLAGS) -o $@/$@ $@/*.o $($@-libs)
	$(STRIP) $@/$@
