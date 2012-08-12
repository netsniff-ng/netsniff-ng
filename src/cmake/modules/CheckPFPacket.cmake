#
# netsniff-ng - the packet sniffing beast
# By Daniel Borkmann <daniel@netsniff-ng.org>
# Copyright 2011 Emmanuel Roullit <emmanuel@netsniff-ng.org>.
# Copyright 2009 Aaron Turner, <aturner@synfin.net>, 3-clause BSD
# Subject to the GPL, version 2.
#

include(CheckCSourceRuns)

check_c_source_runs("
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	int sock;
	sock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	exit(0);
}
" PFPACKET_RUN_RESULT)

set(HAVE_PF_PACKET NO)

if(PFPACKET_RUN_RESULT EQUAL 1)
  set(HAVE_PF_PACKET YES)
  message(STATUS "System has PF_PACKET sockets")
else(PFPACKET_RUN_RESULT EQUAL 1)
  message(STATUS "System has no PF_PACKET sockets")
endif(PFPACKET_RUN_RESULT EQUAL 1)
