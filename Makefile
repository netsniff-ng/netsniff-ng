# netsniff-ng build system
# Copyright 2012 - 2013 Daniel Borkmann <borkmann@gnumaniacs.org>
# Copyright 2013 - 2015 Tobias Klauser <tklauser@distanz.ch>
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
PATCHLEVEL = 6
SUBLEVEL = 8
EXTRAVERSION =
NAME = Flutternozzle

TOOLS ?= $(CONFIG_TOOLS)

# For packaging purposes, prefix can define a different path.
PREFIX ?= $(CONFIG_PREFIX)

# Set to use ccache for compilation
CCACHE ?=

# Location of an alternative destination directory for installation
# Useful when cross-compiling and installing in a dedicated target directory
DESTDIR=

# Location of installation paths.
SBINDIR = $(PREFIX)/sbin
INCDIR = $(PREFIX)/include
ETCDIR ?= $(CONFIG_ETCDIR)
ETCDIRE = $(ETCDIR)/netsniff-ng
DATDIR = $(PREFIX)/share/netsniff-ng
MAN8DIR = $(PREFIX)/share/man/man8

# Shut up make, helper warnings, parallel compilation!
MAKEFLAGS += --no-print-directory
MAKEFLAGS += -rR
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --jobs=$(shell grep "^processor" /proc/cpuinfo | wc -l)

# Debugging option
ifeq ("$(origin DEBUG)", "command line")
  DEBUG := 1
else
  ifeq ($(CONFIG_DEBUG), 1)
    DEBUG := 1
  else
    DEBUG := 0
  endif
endif

# Compiler detection
ifneq ($(CC),)
ifeq ($(shell $(CC) -v 2>&1 | grep -c "clang version"), 1)
COMPILER := clang
else
COMPILER := gcc
endif
export COMPILER
endif

# For packaging purposes, you might want to call your own:
#   make CFLAGS="<flags>"
CFLAGS_DEF  = -std=gnu99
CFLAGS_DEF += -pipe

ifeq ($(DEBUG), 1)
  CFLAGS_DEF += -g
  CFLAGS_DEF += -O0
  CFLAGS_DEF += -fno-omit-frame-pointer
else
  CFLAGS_DEF += -O2
  CFLAGS_DEF += -fomit-frame-pointer
  CFLAGS_DEF += -fno-strict-aliasing
  CFLAGS_DEF += -fasynchronous-unwind-tables
  ifneq ($(COMPILER), clang)
    CFLAGS_DEF += -fno-delete-null-pointer-checks
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

CFLAGS_MIN  = -D_REENTRANT
CFLAGS_MIN += -D_LARGEFILE_SOURCE
CFLAGS_MIN += -D_LARGEFILE64_SOURCE
CFLAGS_MIN += -D_FILE_OFFSET_BITS=64
CFLAGS_MIN += -DVERSION_STRING=\"$(VERSION_STRING)\"
CFLAGS_MIN += -DVERSION_LONG=\"$(VERSION_LONG)\"
CFLAGS_MIN += -DETCDIRE_STRING=\"$(ETCDIRE)\"
CFLAGS_MIN += -DDATDIR_STRING=\"$(DATDIR)\"

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

CHECKFLAGS = -D__linux__ -Dlinux -D__STDC__ -Dunix -D__unix \
	     -Wbitwise -Wnoreturn-void

VERSION_SHORT  =  $(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)
VERSION_STRING = "$(VERSION_SHORT)$(CONFIG_RC)"
VERSION_LONG   = "$(VERSION_SHORT)$(CONFIG_RC) ($(NAME))"

export VERSION PATCHLEVEL SUBLEVEL EXTRAVERSION
export DEBUG HARDENING

ifneq ("$(TERM)", "")
  bold   = $(shell tput bold)
  normal = $(shell tput sgr0)
else
  bold   =
  normal =
endif

ifneq ("$(CROSS_COMPILE)", "")
  WHAT := Cross-compiling
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
	$(Q)$(call INSTD,$(DESTDIR)$(DATDIR))
install_allbutcurvetun: $(foreach tool,$(filter-out curvetun,$(TOOLS)),$(tool)_install)
install_allbutmausezahn: $(foreach tool,$(filter-out mausezahn,$(TOOLS)),$(tool)_install)
uninstall: $(foreach tool,$(TOOLS),$(tool)_uninstall)

%.yy.o: %.l
	$(LEXQ) -P $(shell sed -rn 's/.*lex-func-prefix:\s([a-z]+).*/\1/gp' $<) \
	        -o $(BUILD_DIR)/$(shell basename $< .l).yy.c $(LEX_FLAGS) $<
%.tab.o: %.y
	$(YACCQ) -p $(shell sed -rn 's/.*yacc-func-prefix:\s([a-z]+).*/\1/gp' $<) \
		 -o $(BUILD_DIR)/$(shell basename $< .y).tab.c $(YAAC_FLAGS) -d $<

$(foreach tool,$(TOOLS),$(eval $(call TOOL_templ,$(tool))))

%:: ;

$(TOOLS):
	$(LDQ) $(LDFLAGS) -o $@/$@ $(shell LC_ALL=C ls $@/*.o) $($@-libs)
