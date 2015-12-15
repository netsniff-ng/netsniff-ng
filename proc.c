#define _GNU_SOURCE
#include <sched.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "proc.h"
#include "die.h"

void cpu_affinity(int cpu)
{
	int ret;
	cpu_set_t cpu_bitmask;

	CPU_ZERO(&cpu_bitmask);
	CPU_SET(cpu, &cpu_bitmask);

	ret = sched_setaffinity(getpid(), sizeof(cpu_bitmask),
				&cpu_bitmask);
	if (ret)
		panic("Can't set this cpu affinity!\n");
}

int set_proc_prio(int priority)
{
	int ret = setpriority(PRIO_PROCESS, getpid(), priority);
	if (ret)
		panic("Can't set nice val to %i!\n", priority);

	return 0;
}

int set_sched_status(int policy, int priority)
{
	int ret, min_prio, max_prio;
	struct sched_param sp;

	max_prio = sched_get_priority_max(policy);
	min_prio = sched_get_priority_min(policy);

	if (max_prio == -1 || min_prio == -1)
		printf("Cannot determine scheduler prio limits!\n");
	else if (priority < min_prio)
		priority = min_prio;
	else if (priority > max_prio)
		priority = max_prio;

	memset(&sp, 0, sizeof(sp));
	sp.sched_priority = priority;

	ret = sched_setscheduler(getpid(), policy, &sp);
	if (ret) {
		printf("Cannot set scheduler policy!\n");
		return -EINVAL;
	}

	ret = sched_setparam(getpid(), &sp);
	if (ret) {
		printf("Cannot set scheduler prio!\n");
		return -EINVAL;
	}

	return 0;
}

ssize_t proc_get_cmdline(unsigned int pid, char *cmdline, size_t len)
{
	ssize_t ret;
	char path[1024];

	snprintf(path, sizeof(path), "/proc/%u/exe", pid);
	ret = readlink(path, cmdline, len - 1);
	if (ret < 0)
		cmdline[0] = '\0';
	else
		cmdline[ret] = '\0';

	return ret;
}

int proc_exec(const char *proc, char *const argv[])
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	} else if (pid == 0) {
		if (execvp(proc, argv) < 0)
			fprintf(stderr, "Failed to exec: %s\n", proc);
		_exit(1);
	}

	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		return -2;
	}

	if (!WIFEXITED(status))
		return -WEXITSTATUS(status);

	return 0;
}
