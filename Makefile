# netsniff-ng build system
# Copyright 2012 - 2013 Daniel Borkmann <borkmann@gnumaniacs.org>
# Copyright 2013 Tobias Klauser <tklauser@distanz.ch>
# Subject to the GNU GPL, version 2.

-include Config
-include Cmds
-include Extra
-include Template
-include Misc

ifndef CONFIG_OK
  $(error "Please run `./configure' before `make'")
endif

VERSION = 0
PATCHLEVEL = 5
SUBLEVEL = 8
EXTRAVERSION = -rc5
NAME = Ziggomatic

TOOLS ?= $(CONFIG_TOOLS)
TOOLS ?= netsniff-ng trafgen astraceroute flowtop ifpps bpfc curvetun mausezahn

# For packaging purposes, prefix can define a different path.
PREFIX ?=

# Disable if you don't want it
CCACHE ?= $(CONFIG_CCACHE)

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
  CFLAGS_DEF += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
  CFLAGS_DEF += -fexceptions
endif

CFLAGS_DEF += -fomit-frame-pointer
CFLAGS_DEF += -fno-strict-aliasing
CFLAGS_DEF += -fasynchronous-unwind-tables
CFLAGS_DEF += -fno-delete-null-pointer-checks

CFLAGS_MIN  = -D_REENTRANT
CFLAGS_MIN += -D_LARGEFILE_SOURCE
CFLAGS_MIN += -D_LARGEFILE64_SOURCE
CFLAGS_MIN += -D_FILE_OFFSET_BITS=64
CFLAGS_MIN += -DVERSION_STRING=\"$(VERSION_STRING)\"
CFLAGS_MIN += -DVERSION_LONG=\"$(VERSION_LONG)\"
CFLAGS_MIN += -DPREFIX_STRING=\"$(PREFIX)\"

WFLAGS_DEF  = -Wall

CPPFLAGS  ?=
CFLAGS    ?= $(CFLAGS_DEF) $(WFLAGS_DEF) $(CPPFLAGS)
override CFLAGS += $(CFLAGS_MIN) -I.

LEX_FLAGS  =
YAAC_FLAGS =

LDFLAGS   ?=
ifeq ("$(origin CROSS_LD_LIBRARY_PATH)", "command line")
  LDFLAGS += -L$(CROSS_LD_LIBRARY_PATH)
endif

VERSION_SHORT  =  $(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)
VERSION_STRING = "$(VERSION_SHORT)$(CONFIG_RC)"
VERSION_LONG   = "$(VERSION_SHORT)$(CONFIG_RC) ($(NAME))"

export VERSION PATCHLEVEL SUBLEVEL EXTRAVERSION
export CROSS_COMPILE
export DEBUG DISTRO HARDENING

bold   = $(shell tput bold)
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

.PHONY: all toolkit $(TOOLS) clean %_prehook %_clean %_install %_uninstall tag tags cscope
.IGNORE: %_clean_custom %_install_custom
.NOTPARALLEL: $(TOOLS)
.DEFAULT_GOAL := all
.DEFAULT:
.FORCE:

all: build_showinfo toolkit
allbutcurvetun: $(filter-out curvetun,$(TOOLS))
allbutmausezahn: $(filter-out mausezahn,$(TOOLS))
toolkit: $(TOOLS)
clean: $(foreach tool,$(TOOLS),$(tool)_clean)
distclean: clean
	$(Q)$(call RM,Config)
	$(Q)$(call RM,config.h)
	$(Q)$(call RM,config.log)
	$(Q)$(call RM,cov-int)
	$(Q)$(call RM,netsniff-ng-coverity.tgz)
mrproper: distclean
	$(Q)$(GIT_REM)

install: install_all
install_all: $(foreach tool,$(TOOLS),$(tool)_install)
install_allbutcurvetun: $(foreach tool,$(filter-out curvetun,$(TOOLS)),$(tool)_install)
install_allbutmausezahn: $(foreach tool,$(filter-out mausezahn,$(TOOLS)),$(tool)_install)
uninstall: $(foreach tool,$(TOOLS),$(tool)_uninstall)

%.yy.o: %.l
	$(LEX) -P $(shell perl -wlne 'print $$1 if /lex-func-prefix:\s([a-z]+)/' $<) \
	       -o $(BUILD_DIR)/$(shell basename $< .l).yy.c $(LEX_FLAGS) $<
%.tab.o: %.y
	$(YAAC) -p $(shell perl -wlne 'print $$1 if /yaac-func-prefix:\s([a-z]+)/' $<) \
		-o $(BUILD_DIR)/$(shell basename $< .y).tab.c $(YAAC_FLAGS) -d $<

$(foreach tool,$(TOOLS),$(eval $(call TOOL_templ,$(tool))))

%:: ;

$(TOOLS):
	$(LD) $(LDFLAGS) -o $@/$@ $@/*.o $($@-libs)
	$(STRIP) $@/$@
