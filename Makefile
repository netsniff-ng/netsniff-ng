# netsniff-ng build system
# Copyright 2012 - 2013 Daniel Borkmann <borkmann@gnumaniacs.org>
# Subject to the GNU GPL, version 2.

VERSION = 0
PATCHLEVEL = 5
SUBLEVEL = 8
EXTRAVERSION = -rc0
NAME = Ziggomatic

TOOLS ?= netsniff-ng trafgen astraceroute flowtop ifpps bpfc curvetun mausezahn

# For packaging purposes, prefix can define a different path.
PREFIX ?=

# Disable if you don't want it
CCACHE ?= ccache

# Location of installation paths.
SBINDIR = $(PREFIX)/usr/sbin
INCDIR = $(PREFIX)/usr/include
ETCDIR = $(PREFIX)/etc
ETCDIRE = $(ETCDIR)/netsniff-ng
MAN8DIR = $(PREFIX)/usr/share/man/man8

# Shut up make, helper warnings, parallel compilation!
MAKEFLAGS += --no-print-directory
MAKEFLAGS += -rR
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --jobs=$(shell grep "^processor" /proc/cpuinfo | wc -l)

# Debugging option
ifeq ("$(origin DEBUG)", "command line")
  DEBUG := 1
else
  DEBUG := 0
endif

# For packaging purposes, you might want to call your own:
#   make CFLAGS="<flags>"
CFLAGS_DEF  = -std=gnu99
CFLAGS_DEF += -pipe

ifeq ($(DEBUG), 1)
  CFLAGS_DEF += -O2
  CFLAGS_DEF += -g
else
 ifeq ($(DISTRO), 1)
  CFLAGS_DEF += -O2
 else
  CFLAGS_DEF += -march=native
  CFLAGS_DEF += -mtune=native
  CFLAGS_DEF += -O3
 endif
endif
ifeq ($(HARDENING), 1)
  CFLAGS_DEF += -fPIE -pie
  CFLAGS_DEF += -Wl,-z,relro,-z,now
  CFLAGS_DEF += -fstack-protector-all
  CFLAGS_DEF += -Wstack-protector
  CFLAGS_DEF += --param=ssp-buffer-size=4
  CFLAGS_DEF += -ftrapv
  CFLAGS_DEF += -D_FORTIFY_SOURCE=2
  CFLAGS_DEF += -fexceptions
endif

CFLAGS_DEF += -fomit-frame-pointer
CFLAGS_DEF += -fno-strict-aliasing
CFLAGS_DEF += -fasynchronous-unwind-tables
CFLAGS_DEF += -fno-delete-null-pointer-checks

CFLAGS_DEF += -D_REENTRANT
CFLAGS_DEF += -D_LARGEFILE_SOURCE
CFLAGS_DEF += -D_LARGEFILE64_SOURCE
CFLAGS_DEF += -D_FILE_OFFSET_BITS=64

WFLAGS_DEF  = -Wall
WFLAGS_DEF += -Wformat=2
WFLAGS_DEF += -Wmissing-prototypes
WFLAGS_DEF += -Wdeclaration-after-statement
WFLAGS_DEF += -Werror-implicit-function-declaration
WFLAGS_DEF += -Wstrict-prototypes
WFLAGS_DEF += -Wimplicit-int
WFLAGS_DEF += -Wundef

WFLAGS_EXTRA  = -Wno-unused-result
WFLAGS_EXTRA += -Wmissing-parameter-type
WFLAGS_EXTRA += -Wtype-limits
WFLAGS_EXTRA += -Wclobbered
WFLAGS_EXTRA += -Wmissing-field-initializers
WFLAGS_EXTRA += -Woverride-init
WFLAGS_EXTRA += -Wold-style-declaration
WFLAGS_EXTRA += -Wignored-qualifiers
WFLAGS_EXTRA += -Wempty-body
WFLAGS_EXTRA += -Wuninitialized

WFLAGS_DEF += $(WFLAGS_EXTRA)
CFLAGS_DEF += $(WFLAGS_DEF)

CFLAGS    ?= $(CFLAGS_DEF)
CPPFLAGS  ?=
LEX_FLAGS  =
YAAC_FLAGS =
LDFLAGS   ?=
ifeq ("$(origin CROSS_LD_LIBRARY_PATH)", "command line")
  LDFLAGS += -L$(CROSS_LD_LIBRARY_PATH)
endif

ALL_LDFLAGS = $(LDFLAGS)
ALL_CFLAGS = $(CFLAGS) $(CPPFLAGS) -I.
ALL_CFLAGS += -DVERSION_STRING=\"$(VERSION_STRING)\"
ALL_CFLAGS += -DVERSION_LONG=\"$(VERSION_LONG)\"
ALL_CFLAGS += -DPREFIX_STRING=\"$(PREFIX)\"
ifneq ($(wildcard /usr/include/linux/net_tstamp.h),)
  ALL_CFLAGS += -D__WITH_HARDWARE_TIMESTAMPING
endif

VERSION_STRING = $(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)
VERSION_LONG = $(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)~$(NAME)

# Be quite and do not echo the cmd
Q = @

# GCC related stuff
LD = $(Q)echo -e "  LD\t$@" && $(CCACHE) $(CROSS_COMPILE)gcc
CCNQ = $(CCACHE) $(CROSS_COMPILE)gcc
CC = $(Q)echo -e "  CC\t$<" && $(CCNQ)
ifeq ($(DEBUG), 1)
  STRIP = $(Q)true
else
  STRIP = $(Q)echo -e "  STRIP\t$@" && $(CROSS_COMPILE)strip
endif

# Flex/bison related
LEX = $(Q)echo -e "  LEX\t$<" && flex
YAAC = $(Q)echo -e "  YAAC\t$<" && bison

# Installation related
INST = echo -e "  INST\t$(1)" && install -d $(2) && \
	install --mode=644 -DC $(1) $(2)/$(shell basename $(1))

ifeq ("$(origin PREFIX)", "command line")
  INSTX = echo -e "  INST\t$(1)" && install -d $(2) && \
	install -C $(1) $(2)/$(shell basename $(1))
else
  INSTX = echo -e "  INST\t$(1)" && install -C $(1) $(2)/$(shell basename $(1))
endif

RM = echo -e "  RM\t$(1)" && rm -rf $(1)
RMDIR = echo -e "  RM\t$(1)" && rmdir --ignore-fail-on-non-empty $(1) 2> /dev/null || true

GZIP = gzip --best -c

# Git related
GIT_ARCHIVE = git archive --prefix=netsniff-ng-$(VERSION_STRING)/ $(VERSION_STRING) | \
	      $(1) > ../netsniff-ng-$(VERSION_STRING).tar.$(2)
GIT_TAG = git tag -a $(VERSION_STRING) -s -m "tools: $(VERSION_STRING) release"
GIT_LOG = git shortlog -n --not $(shell git describe --abbrev=0 --tags)
GIT_REM = git ls-files -o | xargs rm -rf
GIT_PEOPLE = git log --no-merges $(VERSION_STRING)..HEAD | grep Author: | cut -d: -f2 | \
	     cut -d\< -f1 | sort | uniq -c | sort -nr

export VERSION PATCHLEVEL SUBLEVEL EXTRAVERSION
export CROSS_COMPILE

bold = $(shell tput bold)
normal = $(shell tput sgr0)

ifeq ("$(origin CROSS_COMPILE)", "command line")
  WHAT := Cross compiling
else
  WHAT := Building
endif

build_showinfo:
	$(Q)echo "$(bold)$(WHAT) netsniff-ng toolkit ($(VERSION_STRING)) for" \
	      $(shell $(CCNQ) -dumpmachine)":$(normal)"
clean_showinfo:
	$(Q)echo "$(bold)Cleaning netsniff-ng toolkit ($(VERSION_STRING)):$(normal)"

%.yy.o: %.l
	$(LEX) -P $(shell perl -wlne 'print $$1 if /lex-func-prefix:\s([a-z]+)/' $<) \
	       -o $(BUILD_DIR)/$(shell basename $< .l).yy.c $(LEX_FLAGS) $<
%.tab.o: %.y
	$(YAAC) -p $(shell perl -wlne 'print $$1 if /yaac-func-prefix:\s([a-z]+)/' $<) \
		-o $(BUILD_DIR)/$(shell basename $< .y).tab.c $(YAAC_FLAGS) -d $<

.PHONY: all toolkit $(TOOLS) clean %_prehook %_distclean %_clean %_install tag tags cscope
.FORCE:
.DEFAULT_GOAL := all
.DEFAULT:
.IGNORE: %_clean_custom %_install_custom
.NOTPARALLEL: $(TOOLS)

NCONF_FILES = ether.conf tcp.conf udp.conf oui.conf geoip.conf

all: build_showinfo toolkit
allbutcurvetun: $(filter-out curvetun,$(TOOLS))
allbutmausezahn: $(filter-out mausezahn,$(TOOLS))
toolkit: $(TOOLS)
install: install_all
install_all: $(foreach tool,$(TOOLS),$(tool)_install)
install_allbutcurvetun: $(foreach tool,$(filter-out curvetun,$(TOOLS)),$(tool)_install)
install_allbutmausezahn: $(foreach tool,$(filter-out mausezahn,$(TOOLS)),$(tool)_install)
clean mostlyclean: $(foreach tool,$(TOOLS),$(tool)_clean)
realclean distclean clobber: $(foreach tool,$(TOOLS),$(tool)_distclean)
	$(Q)$(call RMDIR,$(ETCDIRE))
mrproper: clean distclean
	$(Q)$(GIT_REM)

define TOOL_templ
  include $(1)/Makefile
  $(1) $(1)%: BUILD_DIR := $(1)
  $(1)_prehook:
	$(Q)echo "$(bold)$(WHAT) $(1):$(normal)"
  $(1): $(1)_prehook $$($(1)-lex) $$($(1)-yaac) $$(patsubst %.o,$(1)/%.o,$$($(1)-objs))
  $(1)_clean: $(1)_clean_custom
	$(Q)$$(call RM,$(1)/*.o $(1)/$(1) $(1)/*.gz)
  $(1)_install: $(1)_install_custom
	$(Q)$$(call INSTX,$(1)/$(1),$$(SBINDIR))
	$(Q)$(GZIP) $(1).8 > $(1)/$(1).8.gz
	$(Q)$$(call INSTX,$(1)/$(1).8.gz,$$(MAN8DIR))
  $(1)_distclean: $(1)_distclean_custom
	$(Q)$$(call RM,$$(SBINDIR)/$(1))
	$(Q)$$(call RM,$$(MAN8DIR)/$(1).8.gz)
  $(1)/%.yy.o: $(1)/%.yy.c
	$$(CC) $$(ALL_CFLAGS) -o $$@ -c $$<
  $(1)/%.tab.o: $(1)/%.tab.c
	$$(CC) $$(ALL_CFLAGS) -o $$@ -c $$<
  $(1)/%.o: %.c
	$$(CC) $$(ALL_CFLAGS) -o $(1)/$$(shell basename $$@) -c $$<
endef

$(foreach tool,$(TOOLS),$(eval $(call TOOL_templ,$(tool))))

%:: ;

netsniff-ng: ALL_CFLAGS += $(shell pkg-config --cflags libnl-3.0) $(shell pkg-config --cflags libnl-genl-3.0) -D__WITH_PROTOS -D__WITH_TCPDUMP_LIKE_FILTER
trafgen: ALL_CFLAGS += -I.. $(shell pkg-config --cflags libnl-3.0) $(shell pkg-config --cflags libnl-genl-3.0) -D__WITH_PROTOS
ifpps: ALL_CFLAGS += $(shell pkg-config --cflags ncurses)
flowtop: ALL_CFLAGS += $(shell pkg-config --cflags ncurses)
bpfc: ALL_CFLAGS += -I..
curvetun: ALL_CFLAGS += -I ${NACL_INC_DIR}
curvetun: ALL_LDFLAGS += -L ${NACL_LIB_DIR}
# This gets some extra treatment here until the code looks properly
mausezahn: ALL_CFLAGS = -O2 -I. -I.. -DVERSION_STRING=\"$(VERSION_STRING)\" -DPREFIX_STRING=\"$(PREFIX)\" -DVERSION_LONG=\"$(VERSION_LONG)\"

bpfc_clean_custom:
	$(Q)$(call RM,$(BUILD_DIR)/*.h $(BUILD_DIR)/*.c)
trafgen_clean_custom:
	$(Q)$(call RM,$(BUILD_DIR)/*.h $(BUILD_DIR)/*.c)
netsniff-ng_distclean_custom flowtop_distclean_custom:
	$(Q)$(foreach file,$(NCONF_FILES),$(call RM,$(ETCDIRE)/$(file));)
	$(Q)$(call RMDIR,$(ETCDIRE))
trafgen_distclean_custom:
	$(Q)$(call RM,$(ETCDIRE)/stddef.h)
	$(Q)$(call RMDIR,$(ETCDIRE))
astraceroute_distclean_custom:
	$(Q)$(call RM,$(ETCDIRE)/geoip.conf)
	$(Q)$(call RMDIR,$(ETCDIRE))

netsniff-ng_install_custom flowtop_install_custom:
	$(Q)$(foreach file,$(NCONF_FILES),$(call INST,$(file),$(ETCDIRE));)
trafgen_install_custom:
	$(Q)$(call INST,trafgen_stddef.h,$(ETCDIRE))
	$(Q)ln -fs $(ETCDIRE)/trafgen_stddef.h $(ETCDIRE)/stddef.h
astraceroute_install_custom:
	$(Q)$(call INST,geoip.conf,$(ETCDIRE))

$(TOOLS):
	$(LD) $(ALL_LDFLAGS) -o $@/$@ $@/*.o $($@-libs)
	$(STRIP) $@/$@

nacl:
	$(Q)echo "$(bold)$(WHAT) $@:$(normal)"
	$(Q)cd curvetun/ && ./nacl_build.sh ~/nacl
	$(Q)source ~/.bashrc

tarball.gz:  ; $(call GIT_ARCHIVE,gzip,gz)
tarball.bz2: ; $(call GIT_ARCHIVE,bzip2,bz2)
tarball.xz:  ; $(call GIT_ARCHIVE,xz,xz)
tarball: tarball.gz tarball.bz2 tarball.xz

tag:
	$(GIT_TAG)

announcement:
	$(Q)echo -e "netsniff-ng $(VERSION_STRING) has been released to the public (http://netsniff-ng.org/).\n" > .MAIL_MSG
	$(Q)echo -e "It can be fetched via Git, through:\n" >> .MAIL_MSG
	$(Q)echo -e "   git clone git://github.com/borkmann/netsniff-ng.git" >> .MAIL_MSG
	$(Q)echo -e "   git checkout $(VERSION_STRING)\n" >> .MAIL_MSG
	$(Q)echo -e "Or via HTTP, through:\n" >> .MAIL_MSG
	$(Q)echo -e "   wget http://pub.netsniff-ng.org/netsniff-ng/netsniff-ng-$(VERSION_STRING).tar.gz\n" >> .MAIL_MSG
	$(Q)echo -e "The release be verified via Git, through (see README):\n" >> .MAIL_MSG
	$(Q)echo -e "   git tag -v $(VERSION_STRING)\n" >> .MAIL_MSG
	$(Q)echo -e "Major high-level changes since the last release are:\n" >> .MAIL_MSG
	$(Q)echo -e "   *** BLURB HERE ***\n" >> .MAIL_MSG
	$(Q)echo -e "Contributors since last release:\n" >> .MAIL_MSG
	$(GIT_PEOPLE) >> .MAIL_MSG
	$(Q)echo -e "Git changelog since the last release:\n" >> .MAIL_MSG
	$(GIT_LOG) >> .MAIL_MSG

release: announcement tag tarball
	$(Q)echo "Released $(bold)$(VERSION_STRING)$(normal)"

FIND_SOURCE_FILES = ( git ls-files '*.[hcS]' 2>/dev/null || \
			find . \( -name .git -type d -prune \) \
				-o \( -name '*.[hcS]' -type f -print \) )

tags ctags:
	$(Q)$(call RM,tags)
	$(FIND_SOURCE_FILES) | xargs ctags -a

cscope:
	$(Q)$(call RM,cscope*)
	$(FIND_SOURCE_FILES) | xargs cscope -b

help:
	$(Q)echo "$(bold)Available tools from the toolkit:$(normal)"
	$(Q)echo " <toolnames>:={$(TOOLS)}"
	$(Q)echo "$(bold)Targets for building the toolkit:$(normal)"
	$(Q)echo " all|toolkit                  - Build the whole toolkit"
	$(Q)echo " allbutcurvetun               - Build all except curvetun"
	$(Q)echo " allbutmausezahn              - Build all except mausezahn"
	$(Q)echo " <toolname>                   - Build only one of the tools"
	$(Q)echo "$(bold)Targets for cleaning the toolkit's build files:$(normal)"
	$(Q)echo " clean|mostlyclean            - Remove all build files"
	$(Q)echo " <toolname>_clean             - Remove only one of the tool's files"
	$(Q)echo "$(bold)Targets for installing the toolkit:$(normal)"
	$(Q)echo " install                      - Install the whole toolkit"
	$(Q)echo " <toolname>_install           - Install only one of the tools"
	$(Q)echo "$(bold)Targets for removing the toolkit:$(normal)"
	$(Q)echo " realclean|distclean|clobber  - Remove the whole toolkit from the system"
	$(Q)echo " <toolname>_distclean         - Remove only one of the tools"
	$(Q)echo " mrproper                     - Remove build and install files"
	$(Q)echo "$(bold)Hacking/development targets:$(normal)"
	$(Q)echo " tag                          - Generate Git tag of current version"
	$(Q)echo " tarball                      - Generate tarball of latest version"
	$(Q)echo " release                      - Generate a new release"
	$(Q)echo " tags                         - Generate sparse ctags"
	$(Q)echo " cscope                       - Generate cscope files"
	$(Q)echo "$(bold)Misc targets:$(normal)"
	$(Q)echo " nacl                         - Execute the build_nacl script"
	$(Q)echo " help                         - Show this help"
	$(Q)echo "$(bold)Available parameters:$(normal)"
	$(Q)echo " DEBUG=1 / DISTRO=1           - Enable debugging / Build for distros"
	$(Q)echo " HARDENING=1                  - Enable GCC hardening of executables"
	$(Q)echo " PREFIX=/path                 - Install path prefix"
	$(Q)echo " CROSS_COMPILE=/path-prefix   - Kernel-like cross-compiling prefix"
	$(Q)echo " CROSS_LD_LIBRARY_PATH=/path  - Library search path for cross-compiling"
	$(Q)echo " CC=cgcc                      - Use sparse compiler wrapper"
	$(Q)echo " CFLAGS=\"-O2 -Wall ...\"       - Overwrite CFLAGS for compilation"
	$(Q)echo " CPPFLAGS=\"-I <path> ...\"     - Additional CFLAGS for compilation"
	$(Q)echo " LDFLAGS=\"-L <path> ...\"      - Additional LDFLAGS for compilation"
	$(Q)echo " CCACHE=                      - Do not use ccache for compilation"
	$(Q)echo " Q=                           - Show verbose garbage"
