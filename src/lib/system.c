/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
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

	assert(str);

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
		err("Can't set this cpu affinity: %s", str);
		exit(EXIT_FAILURE);
	}

	return (0);
}

/**
 * set_cpu_affinity_inv - Sets inverted CPU affinity according to given param
 * @str:                 option parameter
 */
int set_cpu_affinity_inv(const char *str)
{
	int ret, i, npc;
	const char *p, *q;
	cpu_set_t cpu_bitmask;

	assert(str);

	q = str;

	CPU_ZERO(&cpu_bitmask);

	for (i = 0, npc = sysconf(_SC_NPROCESSORS_CONF); i < npc; ++i) {
		CPU_SET(i, &cpu_bitmask);
	}

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
			CPU_CLR(a, &cpu_bitmask);
			a += s;
		}
	}

	ret = sched_setaffinity(getpid(), sizeof(cpu_bitmask), &cpu_bitmask);
	if (ret) {
		err("Can't set this cpu affinity: %s", str);
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

	assert(cpu_string);
	assert(len == sysconf(_SC_NPROCESSORS_CONF) + 1);

	memset(cpu_string, 0, len);
	CPU_ZERO(&cpu_bitmask);

	ret = sched_getaffinity(getpid(), sizeof(cpu_bitmask), &cpu_bitmask);
	if (ret) {
		err("Can't fetch cpu affinity");
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
		err("Can't set nice val %i", priority);
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
		err("Cannot determine max/min scheduler prio");
	} else if (priority < min_prio) {
		priority = min_prio;
	} else if (priority > max_prio) {
		priority = max_prio;
	}

	memset(&sp, 0, sizeof(sp));
	sp.sched_priority = priority;

	ret = sched_setscheduler(getpid(), policy, &sp);
	if (ret) {
		err("Cannot set scheduler policy");
		return (1);
	}

	ret = sched_setparam(getpid(), &sp);
	if (ret) {
		err("Cannot set scheduler prio");
		return (1);
	}

	return (0);
}

/**
 * check_for_root - Checks user ID for root
 */
void check_for_root(void)
{
	if (geteuid() != 0) {
		warn("Not root?! You shall not pass!\n");
		exit(EXIT_FAILURE);
	}
}

/**
 * start_server - Detached server thread for Daemon
 * @arg:         nullbuff
 */
void *start_server(void *arg)
{
	/* Originally the AF_UNIX socket was here and it was 
	   a dead end! In future, this will be replaced by the
	   netlink protocol suite. */
	pthread_exit(0);
}

/**
 * undaemonize - Undaemonizes the system daemon
 * @pidfile:    path to pidfile
 */
int undaemonize(const char *pidfile)
{
	assert(pidfile);
	unlink(pidfile);
	return (0);
}

/**
 * daemonize - Creates system daemon
 * @pidfile:  path to pidfile
 * @logfile:  path to logfile
 * @sockfile: path to unix domain socket inode
 */
int daemonize(const char *pidfile)
{
	int fd;
	int ret;
	int cpid_len;
	int bytes_written;

	char cpid[32] = { 0 };

	pthread_t tid;
	pthread_attr_t attr;

	assert(pidfile);

	fd = open(pidfile, O_RDONLY);
	if (fd > 0) {
		err("Daemon already started." "Kill daemon and delete pid file %s", pidfile);
		close(fd);
		exit(EXIT_FAILURE);
	}

	info("%s %s in running in daemon mode\n", PROGNAME_STRING, VERSION_STRING);

	/* We start from root and redirect all output to /dev/zero */
	if (daemon(0, 0) != 0) {
		err("Cannot daemonize process");
		close(fd);
		exit(EXIT_FAILURE);
	}

	cpid_len = snprintf(cpid, sizeof(cpid), "%d", getpid());

	fd = open(pidfile, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		err("Openening pidfile");
		exit(EXIT_FAILURE);
	}

	bytes_written = write(fd, cpid, cpid_len);
	if (bytes_written != cpid_len) {
		err("Write failed! Only wrote %i", bytes_written);
		close(fd);
		exit(EXIT_FAILURE);
	}

	close(fd);

	pthread_attr_init(&attr);
	pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);

	ret = pthread_create(&tid, NULL, start_server, NULL);
	if (ret < 0) {
		err("Cannot create thread");
		undaemonize(pidfile);
		exit(EXIT_FAILURE);
	}

	pthread_detach(tid);

	info("Unix domain socket server up and running\n");
	return (0);
}
