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

CFLAGS = -fstack-protector \
	 --param=ssp-buffer-size=4 \
	 -fpie \
	 -fno-strict-aliasing \
	 -fexceptions \
	 -fasynchronous-unwind-tables \
	 -fno-delete-null-pointer-checks \
	 -D_FORTIFY_SOURCE=2 \
	 -D_REENTRANT \
	 -D_FILE_OFFSET_BITS=64 \
	 -D_LARGEFILE_SOURCE \
	 -D_LARGEFILE64_SOURCE \
	 -DVERSION_STRING=\"$(VERSION_STRING)\" \
	 -std=gnu99 \
	 -march=native \
	 -mtune=native \
	 -O3 \
	 -g

WFLAGS = -Wall \
	 -Wmissing-prototypes \
	 -Wdeclaration-after-statement \
	 -Werror-implicit-function-declaration \
	 -Wundef \
	 -Wformat=2

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
			   -Wframe-larger-than=2048 \
			   -D__WITH_PROTOS \
			   #-D__WITH_HARDWARE_TIMESTAMPING
trafgen: ALL_CFLAGS += -I.. -I$(INCDIR)/libnl3/ \
		       -Wstrict-prototypes \
		       -Wframe-larger-than=2048 \
		       -D__WITH_PROTOS \
		       #-D__WITH_HARDWARE_TIMESTAMPING
trafgen_clean_custom:
	@rm $(BUILD_DIR)/*.h $(BUILD_DIR)/*.c
astraceroute: ALL_CFLAGS += -Wstrict-prototypes -Wframe-larger-than=2048
flowtop: ALL_CFLAGS += -Wstrict-prototypes -Wframe-larger-than=2048
ifpps: ALL_CFLAGS += -Wstrict-prototypes -Wframe-larger-than=2048
bpfc: ALL_CFLAGS += -I.. -Wstrict-prototypes -Wframe-larger-than=2048
curvetun: ALL_CFLAGS += -Wstrict-prototypes -Wframe-larger-than=2048

$(TOOLS):
	$(LD) $(ALL_LDFLAGS) -o $@/$@ $@/*.o $($@-libs)
	$(STRIP) $@/$@
