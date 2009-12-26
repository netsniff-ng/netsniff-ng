#
# Makefile for netsniff-ng lib
#

CC               = gcc
# Use this for code analysis
#CC               = nccgen -ncgcc -ncld -ncfabs
LIBS             = -lpthread -lrt
INCLUDE          = -I../include
CFLAGS           = -Wall -O2

OBJECTS_LIB      = bpf_code.o export.o misc.o print.o rx_ring.o system.o

all: lib

lib: $(OBJECTS_LIB)

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $<

clean:
	rm *.o || true

