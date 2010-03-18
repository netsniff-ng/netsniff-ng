#
# Makefile for netsniff-ng lib
#

CC               = echo "CC        $<"; \
		   gcc $(ARGS)
LIBS             = -lpthread -lrt
INCLUDE          = -I../include
CFLAGS           = -O2 -fomit-frame-pointer -fno-strict-aliasing -fno-common -fno-delete-null-pointer-checks
CFLAGS		+= -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -Werror-implicit-function-declaration  \
		   -Wno-format-security -Wcomments -Wendif-labels
CFLAGSDBG        = -g -Q -fdump-translation-unit
MAKEFLAGS 	+= --no-print-directory
OBJECTS          = bpf.o misc.o print.o config.o rx_ring.o system.o dump.o hash.o netdev.o tx_ring.o \
		   bootstrap.o replay.o ringbuff.o

all: lib

lib: $(OBJECTS)

%.o: %.c
	@$(CC) -c $(CFLAGS) $(INCLUDE) $<

clean:
	@rm *.o *.tu *.nccout *~ Code.map > /dev/null 2>&1 || true

