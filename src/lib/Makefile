#
# Makefile for netsniff-ng lib
#

CC               = gcc
# Use this for code analysis
#CC               = nccgen -ncgcc -ncld -ncfabs
LIBS             = -lpthread -lrt
INCLUDE          = -I../include
CFLAGS           = -Wall -O2

OBJECTS         := bpf_code.o misc.o print.o rx_ring.o system.o
OBJECTS         += pcap.o bucket_hash.o netdev.o

all: lib

lib: $(OBJECTS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

clean:
	rm *.o *.nccout Code.map || true
