#
# netsniff-ng - the packet sniffing beast
# By Daniel Borkmann <daniel@netsniff-ng.org>
# Copyright 2011 Emmanuel Roullit <emmanuel@netsniff-ng.org>.
# Copyright 2009 Aaron Turner, <aturner@synfin.net>, 3-clause BSD
# Subject to the GPL, version 2.
#

include(CheckCSourceRuns)

check_c_source_runs("
#include <stdlib.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/if_packet.h>

int main(int argc, char *argv[])
{
    int test;
    test = TP_STATUS_SEND_REQUEST;
    exit(0);
}" TX_RING_RUN_RESULT)

set(HAVE_TX_RING NO)

if(TX_RING_RUN_RESULT EQUAL 1)
  set(HAVE_TX_RING YES)
  message(STATUS "System has TX_RING support")
else(TX_RING_RUN_RESULT EQUAL 1)
  message(STATUS "System has no TX_RING support")
endif(TX_RING_RUN_RESULT EQUAL 1)
