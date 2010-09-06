#
# Makefile definitions for netsniff-ng
#

LD_NORM      = echo "LD        $(target)"; \
               gcc
CC_NORM      = echo "CC        $<"; \
               gcc
CC_DEBUG     = echo "DBG       $<"; \
               gcc

LIBS         = -lpthread -lrt
MAKEFLAGS   += --no-print-directory

BINDIR       = usr/sbin
ETCDIR       = etc
MANDIR       = usr/share/man/man8
MANDIR_LOCAL = ../doc

define eq
	$(if $(1:$(2)=),,$(if $(2:$(1)=),,T))
endef

ifneq ($(or $(call eq,$(MAKECMDGOALS),"all"), $(call eq,$(MAKECMDGOALS),"")),)
	LD      = $(LD_NORM) -o
	CC      = $(CC_NORM) -c
	CFLAGS  = -O2 -fomit-frame-pointer -fno-strict-aliasing -fno-common  \
		  -fno-delete-null-pointer-checks -pedantic -std=gnu99
	CFLAGS += -Wall -Werror -Wundef -Wstrict-prototypes -Wno-trigraphs   \
		  -Werror-implicit-function-declaration -Wno-format-security \
		  -Wcomments -Wendif-labels
endif

ifeq ($(MAKECMDGOALS), debug)
	LD      = $(LD_NORM) -o
	CC      = $(CC_DEBUG) -c
	CFLAGS  = -O0 -g -fno-inline -pedantic -std=gnu99
	CFLAGS += -Wall -Werror -Wundef -Wstrict-prototypes -Wno-trigraphs   \
		  -Werror-implicit-function-declaration -Wno-format-security \
		  -Wcomments -Wendif-labels
endif

ifeq ($(MAKECMDGOALS), develop)
	LD      = $(LD_NORM) -o
	CC      = $(CC_NORM) -c
	CFLAGS  = -O2 -fomit-frame-pointer -fno-strict-aliasing -fno-common  \
		  -fno-delete-null-pointer-checks -pedantic -std=gnu99 -g
	CFLAGS += -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs           \
		  -Werror-implicit-function-declaration -Wno-format-security \
		  -Wcomments -Wendif-labels
endif

.PHONY: all

