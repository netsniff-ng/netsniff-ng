#
# Makefile for netsniff-ng lib
#

CC               = gcc $(ARGS)
LIBS             = -lpthread -lrt
INCLUDE          = -I../include -I/usr/src/linux-headers-2.6.32.2/include/ -I/usr/src/linux-headers-2.6.32.2/arch/x86/include/
CFLAGS           = -Wall -O2

OBJECTS         := bpf.o misc.o print.o config.o rx_ring.o system.o
OBJECTS         += dump.o hash.o netdev.o tx_ring.o bootstrap.o
OBJECTS         += replay.o ringbuff.o

all: lib

lib: $(OBJECTS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

clean:
	rm *.o *.tu *.nccout Code.map || true

