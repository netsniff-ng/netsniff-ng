###################################################################
#  $Id: CheckBPF.cmake 2217 2009-02-18 07:11:19Z aturner $
#
#  Copyright (c) 2009 Aaron Turner, <aturner at synfin dot net>
#  All rights reserved.
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
#
###################################################################
# - Find out if the system supports the BPF device
# compile and run test

INCLUDE(CheckCSourceRuns)
check_c_source_runs("
/* runtime test to check for /dev/bpf device which can be used to inject packets */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>

int 
main(int argc, char *argv[]) 
{
    int fd;

    fd = open(\"/dev/bpf0\", O_RDONLY, 0);

    /* if we opened it, we're good */
    if (fd > 1)
        exit(0);

    /* if we got EBUSY or permission denied it exists, so we're good */
    if (fd < 0 && (errno == EBUSY || errno == 13))
        exit(0);

    /* else suck, no good */
    exit(-1);
}
"
    BPF_RUN_RESULT)

SET(HAVE_BPF "")
IF(BPF_RUN_RESULT EQUAL 1)
    SET(HAVE_BPF 1)
    MESSAGE(STATUS "System has BPF sockets")
ELSE(BPF_RUN_RESULT EQUAL 1)
    MESSAGE(STATUS "System does not have BPF sockets")
ENDIF(BPF_RUN_RESULT EQUAL 1)
