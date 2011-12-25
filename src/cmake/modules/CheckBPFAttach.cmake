#
# netsniff-ng - the packet sniffing beast
# By Daniel Borkmann <daniel@netsniff-ng.org>
# Copyright 2011 Emmanuel Roullit <emmanuel@netsniff-ng.org>.
# Subject to the GPL, version 2.
#

INCLUDE(CheckCSourceRuns)
      
CHECK_C_SOURCE_RUNS("
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/filter.h>

int
main(int argc, char *argv[])
{
	struct sock_fprog bpf;
	int empty;
	int sock = 0;

	memset(&bpf, 0, sizeof(bpf));

	setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	setsockopt(sock, SOL_SOCKET, SO_DETACH_FILTER, &empty, sizeof(empty));
	exit(0);
}
"
	BPFATTACH_RUN_RESULT)

SET(HAVE_BPF_ATTACH NO)
IF(BPFATTACH_RUN_RESULT EQUAL 1)
    SET(HAVE_BPF_ATTACH YES)
    MESSAGE(STATUS "System has SO_ATTACH_FILTER/SO_DETACH_FILTER support")
ELSE(BPFATTACH_RUN_RESULT EQUAL 1)
    MESSAGE(STATUS "System does not have SO_ATTACH_FILTER/SO_DETACH_FILTER support")
ENDIF(BPFATTACH_RUN_RESULT EQUAL 1)
