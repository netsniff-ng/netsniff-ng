#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <sched.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

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

static int match_pid_by_inode(pid_t pid, ino_t ino)
{
	struct dirent *ent;
	char path[1024];
	DIR *dir;

	if (snprintf(path, sizeof(path), "/proc/%u/fd", pid) == -1)
		panic("giant process name! %u\n", pid);

	dir = opendir(path);
	if (!dir)
		return -1;

	while ((ent = readdir(dir))) {
		struct stat statbuf;

		if (snprintf(path, sizeof(path), "/proc/%u/fd/%s",
			     pid, ent->d_name) < 0)
			continue;

		if (stat(path, &statbuf) < 0)
			continue;

		if (S_ISSOCK(statbuf.st_mode) && ino == statbuf.st_ino) {
			closedir(dir);
			return 0;
		}
	}

	closedir(dir);
	return -1;
}

int proc_find_by_inode(ino_t ino, char *cmdline, size_t len, pid_t *pid)
{
	struct dirent *ent;
	DIR *dir;

	if (ino <= 0) {
		cmdline[0] = '\0';
		return 0;
	}

	dir = opendir("/proc");
	if (!dir)
		panic("Cannot open /proc: %s\n", strerror(errno));

	while ((ent = readdir(dir))) {
		int ret;
		char *end;
		const char *name = ent->d_name;
		pid_t cur_pid = strtoul(name, &end, 10);

		/* not a PID */
		if (cur_pid == 0 && end == name)
			continue;

		ret = match_pid_by_inode(cur_pid, ino);
		if (!ret) {
			ret = proc_get_cmdline(cur_pid, cmdline, len);
			if (ret < 0)
				panic("Failed to get process cmdline: %s\n", strerror(errno));

			closedir(dir);
			*pid = cur_pid;
			return ret;
		}
	}

	closedir(dir);
	return -1;
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

bool proc_exists(pid_t pid)
{
	struct stat statbuf;
	char path[1024];

	if (snprintf(path, sizeof(path), "/proc/%u", pid) < 0)
		return false;

	return stat(path, &statbuf) == 0;
}
