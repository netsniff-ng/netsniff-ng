#
# Makefile for netsniff-ng lib
#

CC               = gcc $(ARGS)
LIBS             = -lpthread -lrt
INCLUDE          = -I../include
CFLAGS           = -Wall -O2

OBJECTS         := bpf.o misc.o print.o rx_ring.o system.o
OBJECTS         += dump.o hash.o netdev.o tx_ring.o

all: lib

lib: $(OBJECTS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

clean:
	rm *.o *.tu *.nccout Code.map || true

