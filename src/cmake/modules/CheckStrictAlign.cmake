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
/* Code to check for strictly aligned systems like SPARC.  Code based on that
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
		pid = waitpid(pid, &status, 0);
		if (pid < 0)
			exit(3);
		exit(!WIFEXITED(status));
	}

	i = *(unsigned int *)&a[1];
	printf(\"%d\\\\n\", i);

	exit(0);
}" STRICT_ALIGN_RUN_RESULT)

set(FORCE_ALIGN OFF)

if(STRICT_ALIGN_RUN_RESULT EQUAL 1)
  message(STATUS "System has strict alignment")
else(STRICT_ALIGN_RUN_RESULT EQUAL 1)
  set(FORCE_ALIGN 1 FORCE)
  message(STATUS "System has no strict alignment")
endif(STRICT_ALIGN_RUN_RESULT EQUAL 1)
