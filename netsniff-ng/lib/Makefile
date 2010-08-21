#
# Makefile for netsniff-ng lib
#

include ../definitions.mk

INCLUDE  = -I../include

lib-objs = bpf.o misc.o print.o config.o rx_ring.o system.o dump.o hash.o \
	   netdev.o tx_ring.o bootstrap.o replay.o ringbuff.o cursor.o \
	   server.o xmalloc.o strlcpy.o

all: clean build
debug: all
develop: all

#-----------------------------------------------------------------------------

build: $(lib-objs)

#-----------------------------------------------------------------------------

%.o: %.c
	@$(CC) $(CFLAGS) $(INCLUDE) $<

#-----------------------------------------------------------------------------

clean:
	@rm *.o *.tu *.nccout *~ Code.map > /dev/null 2>&1 || true

