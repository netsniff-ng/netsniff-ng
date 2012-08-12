#
# netsniff-ng - the packet sniffing beast
# By Daniel Borkmann <daniel@netsniff-ng.org>
# Copyright 2011 Emmanuel Roullit <emmanuel@netsniff-ng.org>.
# Copyright 2009 Aaron Turner, <aturner@synfin.net>, 3-clause BSD
# Subject to the GPL, version 2.
#

# Copyright (c) 2009 Aaron Turner, <aturner@synfin.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
# * Neither the name of the Aaron Turner nor the names of its
#   contributors may be used to endorse or promote products derived
#   from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

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
