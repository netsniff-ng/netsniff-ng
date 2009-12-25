#
# Makefile for netsniff-ng lib
#

CC               = gcc
LIBS             = -lpthread -lrt
INCLUDE          = -I../include
CFLAGS           = -Wall -O2 -g

OBJECTS_LIB      = bpf_code.o export.o misc.o print.o rx_ring.o system.o

all: lib

lib: $(OBJECTS_LIB)

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

clean:
	rm *.o || true

