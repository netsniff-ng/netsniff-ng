/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4  \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l80 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 *
 * Note: Your kernel has to be compiled with CONFIG_PACKET_MMAP=y option in 
 *       order to use this.
 */

/*
 * Contains: 
 *    System related stuff like tweaking of scheduling params or CPU affinity
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>

#include <sys/resource.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/system.h>

/**
 * nexttoken - Fetches next param token
 * @q:        string
 * @sep:      token separator
 */
static inline const char *nexttoken(const char *q, int sep)
{
	if (q) {
		q = strchr(q, sep);
	}
	if (q) {
		q++;
	}

	return (q);
}

/**
 * set_cpu_affinity - Sets CPU affinity according to given param
 * @str:             option parameter
 */
int set_cpu_affinity(const char *str)
{
	int ret;
	const char *p, *q;
	cpu_set_t cpu_bitmask;

	q = str;

	CPU_ZERO(&cpu_bitmask);

	while (p = q, q = nexttoken(q, ','), p) {
		unsigned int a;	/* Beginning of range */
		unsigned int b;	/* End of range */
		unsigned int s;	/* Stride */

		const char *c1, *c2;

		if (sscanf(p, "%u", &a) < 1) {
			return 1;
		}

		b = a;
		s = 1;

		c1 = nexttoken(p, '-');
		c2 = nexttoken(p, ',');

		if (c1 != NULL && (c2 == NULL || c1 < c2)) {
			if (sscanf(c1, "%u", &b) < 1) {
				return 1;
			}

			c1 = nexttoken(c1, ':');
			if (c1 != NULL && (c2 == NULL || c1 < c2)) {
				if (sscanf(c1, "%u", &s) < 1) {
					return (1);
				}
			}
		}

		if (!(a <= b)) {
			return (1);
		}

		while (a <= b) {
			CPU_SET(a, &cpu_bitmask);
			a += s;
		}
	}

	ret = sched_setaffinity(getpid(), sizeof(cpu_bitmask), &cpu_bitmask);
	if (ret) {
		perr("Can't set this cpu affinity: %s\n", str);
		exit(EXIT_FAILURE);
	}

	return (0);
}

/**
 * get_cpu_affinity - Returns CPU affinity bitstring
 * @cpu_string:      allocated string
 * @len:             len of cpu_string
 */
char *get_cpu_affinity(char *cpu_string, size_t len)
{
	int i, ret;
	int cpu;

	cpu_set_t cpu_bitmask;

	assert(len == sysconf(_SC_NPROCESSORS_CONF) + 1);

	memset(cpu_string, 0, len);
	CPU_ZERO(&cpu_bitmask);

	ret = sched_getaffinity(getpid(), sizeof(cpu_bitmask), &cpu_bitmask);
	if (ret) {
		perr("Can't fetch cpu affinity: %d\n", ret);
		return (NULL);
	}

	for (i = 0; i < len - 1; ++i) {
		cpu = CPU_ISSET(i, &cpu_bitmask);
		cpu_string[i] = (cpu ? '1' : '0');
	}

	return (cpu_string);
}

/**
 * set_proc_prio - Sets nice value
 * @prio:         nice
 */
int set_proc_prio(int priority)
{
	int ret;

	/*
	 * setpriority() is clever, even if you put a nice value which 
	 * is out of range it corrects it to the closest valid nice value
	 */
	ret = setpriority(PRIO_PROCESS, getpid(), priority);
	if (ret) {
		perr("Can't set nice val %i: %d\n", priority, ret);
		exit(EXIT_FAILURE);
	}

	return (0);
}

/**
 * set_sched_status - Sets process scheduler type and priority
 * @policy:          type of scheduling
 * @priority:        scheduling priority (!nice)
 */
int set_sched_status(int policy, int priority)
{
	int ret;
	int min_prio, max_prio;

	struct sched_param sp;

	max_prio = sched_get_priority_max(policy);
	min_prio = sched_get_priority_min(policy);

	if (max_prio == -1 || min_prio == -1) {
		perr("Cannot determine max/min scheduler prio!\n");
	} else if (priority < min_prio) {
		priority = min_prio;
	} else if (priority > max_prio) {
		priority = max_prio;
	}

	memset(&sp, 0, sizeof(sp));
	sp.sched_priority = priority;

	ret = sched_setscheduler(getpid(), policy, &sp);
	if (ret) {
		perr("Cannot set scheduler policy!\n");
		return (1);
	}

	ret = sched_setparam(getpid(), &sp);
	if (ret) {
		perr("Cannot set scheduler prio!\n");
		return (1);
	}

	return (0);
}

/**
 * check_for_root - Checks user ID for root
 */
void check_for_root(void)
{
	int ret;

	ret = geteuid();
	if (ret != 0) {
		err("dude, you are not root!\n");
		exit(EXIT_FAILURE);
	}
}

/**
 * undaemonize - Undaemonizes the system daemon
 * @pidfile:    path to pidfile
 */
int undaemonize(const char *pidfile)
{
	int ret;

	ret = unlink(pidfile);
	if (ret < 0) {
		perr("cannot unlink pidfile - ");
		return (ret);
	}

	return (0);
}

/**
 * daemonize - Creates system daemon
 * @pidfile:  path to pidfile
 * @logfile:  path to logfile
 * @sockfile: path to unix domain socket inode
 */
int daemonize(const char *pidfile, const char *logfile,
	      const char *sockfile, void *(*start_server) (void *sock))
{
	int fd;
	int ret;
	int cpid_len;
	int bytes_written;

	char cpid[32] = { 0 };

	pid_t pid;
	pthread_t tid;
	pthread_attr_t attr;

	assert(pidfile != NULL && logfile != NULL);

	fd = open(pidfile, O_RDONLY);
	if (fd > 0) {
		err("daemon already started."
		    "kill daemon and delete pid file %s\n", pidfile);

		close(fd);
		exit(EXIT_FAILURE);
	}

	umask(022);

	pid = fork();
	if (pid < 0) {
		perr("fork: %d - ", pid);
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	ret = setsid();
	if (ret < 0) {
		perr("setsid: %d - ", ret);
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid < 0) {
		perr("fork: %d - ", pid);
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	ret = chdir("/");
	if (ret < 0) {
		perr("chdir: %d - ", ret);
		exit(EXIT_FAILURE);
	}

	cpid_len = snprintf(cpid, sizeof(cpid), "%d", getpid());

	fd = open(pidfile, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd < 0) {
		perr("open pidfile: %d - ", fd);
		exit(EXIT_FAILURE);
	}

	bytes_written = write(fd, cpid, cpid_len);
	if (bytes_written != cpid_len) {
		perr("write failed only wrote %i: %d - ", bytes_written, fd);

		close(fd);
		exit(EXIT_FAILURE);
	}

	close(fd);

	fd = open(logfile, O_CREAT | O_APPEND | O_WRONLY, 0644);
	if (fd < 0) {
		perr("open logfile: %d - ", fd);
		exit(EXIT_FAILURE);
	}

	if (fd != 2) {
		dup2(fd, 2);
		close(fd);
	}

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		perr("open /dev/null: %d - ", fd);
		exit(EXIT_FAILURE);
	}

	dup2(fd, 0);
	dup2(fd, 1);

	if (!logfile) {
		dup2(fd, 2);
	}

	if (fd > 2) {
		close(fd);
	}

	dbg("%s %s\n", PROGNAME_STRING, VERSION_STRING);
	dbg("daemon up and running\n");

	pthread_attr_init(&attr);
	pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);

	ret = pthread_create(&tid, NULL, start_server, (void *)sockfile);
	if (ret < 0) {
		perr("cannot create thread %d - ", errno);

		undaemonize(pidfile);
		exit(EXIT_FAILURE);
	}

	pthread_detach(tid);

	dbg("unix domain socket server up and running\n");

	return (0);
}
