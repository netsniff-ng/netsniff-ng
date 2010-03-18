#
# Makefile for netsniff-ng lib
#

include ../.config

INCLUDE  = -I../include

lib-objs = bpf.o misc.o print.o config.o rx_ring.o system.o dump.o hash.o netdev.o tx_ring.o \
	   bootstrap.o replay.o ringbuff.o

all: lib

lib: $(lib-objs)

%.o: %.c
	@$(CC) -c $(CFLAGS) $(INCLUDE) $<

clean:
	@rm *.o *.tu *.nccout *~ Code.map > /dev/null 2>&1 || true

