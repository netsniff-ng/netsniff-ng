#
# Makefile definitions for netsniff-ng
# Author: Daniel Borkmann
#

LD_NORM      = echo "LD        $(target)"; \
               gcc -pie -z relo
CC_NORM      = echo "CC        $<";        \
               gcc
CC_DEBUG     = echo "DC        $<";        \
               gcc
A2X_NORM     = echo "A2X   $<";            \
               a2x

MAKEFLAGS   += --no-print-directory

BINDIR       = usr/sbin
ETCDIR       = etc

define eq
	$(if $(1:$(2)=),,$(if $(2:$(1)=),,T))
endef

ifneq ($(or $(call eq,$(MAKECMDGOALS),"all"), $(call eq,$(MAKECMDGOALS),"")),)
	LD      = $(LD_NORM) -o
	CC      = $(CC_NORM) -c
	CFLAGS  = -O2 -fomit-frame-pointer -fno-strict-aliasing -fno-common  \
		  -fno-delete-null-pointer-checks -std=gnu99 -pedantic       \
		  -fstack-protector -D_FORTIFY_SOURCE=2 -fPIE                \
		  -fno-strict-overflow
	CFLAGS += -Wall -Werror -Wundef -Wstrict-prototypes -Wno-trigraphs   \
		  -Werror-implicit-function-declaration -Wno-format-security \
		  -Wcomments -Wendif-labels -Wno-long-long -Wuninitialized   \
		  -Wstrict-overflow
endif

ifeq ($(MAKECMDGOALS), debug)
	LD      = $(LD_NORM) -o
	CC      = $(CC_DEBUG) -c
	CFLAGS  = -O0 -g -fno-inline -std=gnu99 -pedantic -fno-strict-overflow
	CFLAGS += -Wall -Werror -Wundef -Wstrict-prototypes -Wno-trigraphs   \
		  -Werror-implicit-function-declaration -Wno-format-security \
		  -Wcomments -Wendif-labels -Wno-long-long -Wstrict-overflow
endif

.PHONY: all
