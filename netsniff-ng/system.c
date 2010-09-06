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

#include "macros.h"
#include "system.h"

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
