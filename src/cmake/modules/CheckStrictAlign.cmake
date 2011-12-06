###################################################################
#  $Id: CheckStrictAlign.cmake 2217 2009-02-18 07:11:19Z aturner $
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
# - Find out if the system forces strictly aligned memory access
#
# Sets:
# FORCE_ALIGN 1  if true


INCLUDE(CheckCSourceRuns)
check_c_source_runs("
/* 
 * Code to check for strictly aligned systems like SPARC.  Code based on that
 * from libpcap
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>

unsigned char a[5] = { 1, 2, 3, 4, 5 };

int main(int argc, char *argv[]) 
{
    unsigned int i;
    pid_t pid;
    int status;

    /* avoid core dumped message, by using fork() */
    pid = fork();

    if (pid <  0)
        exit(2);

    if (pid > 0) {
        /* parent */
        pid = waitpid(pid, &status, 0);

        if (pid < 0)
            exit(3);

        exit(!WIFEXITED(status));
    }

    /* child */
    i = *(unsigned int *)&a[1];
    printf(\"%d\\\\n\", i);

    exit(0); /* success! */
}
"
    STRICT_ALIGN_RUN_RESULT)


SET(FORCE_ALIGN OFF)
IF(STRICT_ALIGN_RUN_RESULT EQUAL 1)
    MESSAGE(STATUS "System architecture is NOT strictly aligned")
ELSE(STRICT_ALIGN_RUN_RESULT EQUAL 1)
    SET(FORCE_ALIGN 1 FORCE)
    MESSAGE(STATUS "System architecture IS strictly aligned")
ENDIF(STRICT_ALIGN_RUN_RESULT EQUAL 1)
