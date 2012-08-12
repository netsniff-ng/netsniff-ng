#
# netsniff-ng - the packet sniffing beast
# By Daniel Borkmann <daniel@netsniff-ng.org>
# Copyright 2011 Emmanuel Roullit <emmanuel@netsniff-ng.org>.
# Copyright 2009 Aaron Turner, <aturner@synfin.net>, 3-clause BSD
# Subject to the GPL, version 2.
#

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
