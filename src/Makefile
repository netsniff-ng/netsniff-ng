# netsniff-ng build system, part of netsniff-ng.
# Copyright 2012 Daniel Borkmann <borkmann@gnumaniacs.org>
# Subject to the GNU GPL, version 2.

# TODO:
#   - target make tarball
#   - target make test -> libtap(?) this time ...
#   - target make debug

VERSION = 0
PATCHLEVEL = 5
SUBLEVEL = 8
EXTRAVERSION = -rc0

BINDIR = $(PREFIX)/usr/bin
SBINDIR = $(PREFIX)/usr/sbin
INCDIR = $(PREFIX)/usr/include
ETCDIR = $(PREFIX)/etc

MAKEFLAGS += -rR --no-print-directory

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
ifeq ("$(origin CROSS_LD_LIBRARY_PATH)", "command line")
  LDFLAGS = -L$(CROSS_LD_LIBRARY_PATH)
else
  LDFLAGS =
endif

ALL_CFLAGS = $(CFLAGS)
ALL_LDFLAGS = $(LDFLAGS)
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

netsniff-ng-target = netsniff-ng
include $(netsniff-ng-target)/Makefile
netsniff-ng: ALL_CFLAGS += -I$(INCDIR)/libnl3/ -Wstrict-prototypes -Wframe-larger-than=2048 \
	     -D__WITH_PROTOS #-D__WITH_HARDWARE_TIMESTAMPING
netsniff-ng netsniff-ng%: BUILD_DIR = $(netsniff-ng-target)
netsniff-ng_prehook:
	@echo "$(bold)Building $(netsniff-ng-target):$(normal)"
netsniff-ng: netsniff-ng_prehook $(netsniff-ng-objs)
	$(LD) $(ALL_LDFLAGS) -o $@/$@ $(BUILD_DIR)/*.o $(netsniff-ng-libs)
	$(STRIP) $@/$@
netsniff-ng_clean:
	$(RM) -rf $(BUILD_DIR)/*.o $(BUILD_DIR)/$(netsniff-ng-target)
netsniff-ng_install:
	@echo "build dir: $(BUILD_DIR)"
netsniff-ng_distclean:
	@echo "build dir: $(BUILD_DIR)"

trafgen-target = trafgen
include $(trafgen-target)/Makefile
trafgen: ALL_CFLAGS += -I.. -I$(INCDIR)/libnl3/ -Wstrict-prototypes \
	 -Wframe-larger-than=2048 -D__WITH_PROTOS #-D__WITH_HARDWARE_TIMESTAMPING
trafgen trafgen%: BUILD_DIR = $(trafgen-target)
trafgen_prehook:
	@echo "$(bold)Building $(trafgen-target):$(normal)"
trafgen: trafgen_prehook $(trafgen-lex) $(trafgen-yaac) $(trafgen-objs)
	$(LD) $(ALL_LDFLAGS) -o $@/$@ $(BUILD_DIR)/*.o $(trafgen-libs)
	$(STRIP) $@/$@
trafgen_clean:
	$(RM) -rf $(BUILD_DIR)/*.o $(BUILD_DIR)/*.h $(BUILD_DIR)/*.c \
		  $(BUILD_DIR)/$(trafgen-target)
trafgen_install:
	@echo "build dir: $(BUILD_DIR)"
trafgen_distclean:
	@echo "build dir: $(BUILD_DIR)"

astraceroute-target = astraceroute
include $(astraceroute-target)/Makefile
astraceroute: ALL_CFLAGS += -Wstrict-prototypes -Wframe-larger-than=2048
astraceroute astraceroute%: BUILD_DIR = $(astraceroute-target)
astraceroute_prehook:
	@echo "$(bold)Building $(astraceroute-target):$(normal)"
astraceroute: astraceroute_prehook $(astraceroute-objs)
	$(LD) $(ALL_LDFLAGS) -o $@/$@ $(BUILD_DIR)/*.o $(astraceroute-libs)
	$(STRIP) $@/$@
astraceroute_clean:
	$(RM) -rf $(BUILD_DIR)/*.o $(BUILD_DIR)/$(astraceroute-target)
astraceroute_install:
	@echo "build dir: $(BUILD_DIR)"
astraceroute_distclean:
	@echo "build dir: $(BUILD_DIR)"

flowtop-target = flowtop
include $(flowtop-target)/Makefile
flowtop: ALL_CFLAGS += -Wstrict-prototypes -Wframe-larger-than=2048
flowtop flowtop%: BUILD_DIR = $(flowtop-target)
flowtop_prehook:
	@echo "$(bold)Building $(flowtop-target):$(normal)"
flowtop: flowtop_prehook $(flowtop-objs)
	$(LD) $(ALL_LDFLAGS) -o $@/$@ $(BUILD_DIR)/*.o $(flowtop-libs)
	$(STRIP) $@/$@
flowtop_clean:
	$(RM) -rf $(BUILD_DIR)/*.o $(BUILD_DIR)/$(flowtop-target)
flowtop_install:
	@echo "build dir: $(BUILD_DIR)"
flowtop_distclean:
	@echo "build dir: $(BUILD_DIR)"

ifpps-target = ifpps
include $(ifpps-target)/Makefile
ifpps: ALL_CFLAGS += -Wstrict-prototypes -Wframe-larger-than=2048
ifpps ifpps%: BUILD_DIR = $(ifpps-target)
ifpps_prehook:
	@echo "$(bold)Building $(ifpps-target):$(normal)"
ifpps: ifpps_prehook $(ifpps-objs)
	$(LD) $(ALL_LDFLAGS) -o $@/$@ $(BUILD_DIR)/*.o $(ifpps-libs)
	$(STRIP) $@/$@
ifpps_clean:
	$(RM) -rf $(BUILD_DIR)/*.o $(BUILD_DIR)/$(ifpps-target)
ifpps_install:
	@echo "build dir: $(BUILD_DIR)"
ifpps_distclean:
	@echo "build dir: $(BUILD_DIR)"

mausezahn-target = mausezahn
include $(mausezahn-target)/Makefile
mausezahn mausezahn%: BUILD_DIR = $(mausezahn-target)
mausezahn_prehook:
	@echo "$(bold)Building $(mausezahn-target):$(normal)"
mausezahn: mausezahn_prehook $(mausezahn-objs)
	$(LD) $(ALL_LDFLAGS) -o $@/$@ $(BUILD_DIR)/*.o $(mausezahn-libs)
	$(STRIP) $@/$@
mausezahn_clean:
	$(RM) -rf $(BUILD_DIR)/*.o $(BUILD_DIR)/$(mausezahn-target)
mausezahn_install:
	@echo "build dir: $(BUILD_DIR)"
mausezahn_distclean:
	@echo "build dir: $(BUILD_DIR)"

bpfc-target = bpfc
include $(bpfc-target)/Makefile
bpfc: ALL_CFLAGS += -I.. -Wstrict-prototypes -Wframe-larger-than=2048
bpfc bpfc%: BUILD_DIR = $(bpfc-target)
bpfc_prehook:
	@echo "$(bold)Building $(bpfc-target):$(normal)"
bpfc: bpfc_prehook $(bpfc-lex) $(bpfc-yaac) $(bpfc-objs)
	$(LD) $(ALL_LDFLAGS) -o $@/$@ $(BUILD_DIR)/*.o $(bpfc-libs)
	$(STRIP) $@/$@
bpfc_clean:
	$(RM) -rf $(BUILD_DIR)/*.o $(BUILD_DIR)/*.h $(BUILD_DIR)/*.c \
		  $(BUILD_DIR)/$(bpfc-target)
bpfc_install:
	@echo "build dir: $(BUILD_DIR)"
bpfc_distclean:
	@echo "build dir: $(BUILD_DIR)"

curvetun-target = curvetun
include $(curvetun-target)/Makefile
curvetun: ALL_CFLAGS += -Wstrict-prototypes -Wframe-larger-than=2048
curvetun curvetun%: BUILD_DIR = $(curvetun-target)
curvetun_prehook:
	@echo "$(bold)Building $(curvetun-target):$(normal)"
curvetun: curvetun_prehook $(curvetun-objs)
	$(LD) $(ALL_LDFLAGS) -o $@/$@ $(BUILD_DIR)/*.o $(curvetun-libs)
	$(STRIP) $@/$@
curvetun_clean:
	$(RM) -rf $(BUILD_DIR)/*.o $(BUILD_DIR)/$(curvetun-target)
curvetun_install:
	@echo "build dir: $(BUILD_DIR)"
curvetun_distclean:
	@echo "build dir: $(BUILD_DIR)"

toolkit: build_showinfo \
	netsniff-ng \
	trafgen \
	astraceroute \
	flowtop \
	ifpps \
	mausezahn \
	bpfc \
	curvetun

all: toolkit

clean: clean_showinfo \
	netsniff-ng_clean \
	trafgen_clean \
	astraceroute_clean \
	flowtop_clean \
	ifpps_clean \
	mausezahn_clean \
	bpfc_clean \
	curvetun_clean

install: toolkit \
	netsniff-ng_install \
	trafgen_install \
	astraceroute_install \
	flowtop_install \
	ifpps_install \
	mausezahn_install \
	bpfc_install \
	curvetun_install

distclean: netsniff-ng_distclean \
	trafgen_distclean \
	astraceroute_distclean \
	flowtop_distclean \
	ifpps_distclean \
	mausezahn_distclean \
	bpfc_distclean \
	curvetun_distclean

.PHONY: build_showinfo clean_showinfo
.DEFAULT_GOAL := toolkit
