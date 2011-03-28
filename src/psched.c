/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009-2011 Daniel Borkmann.
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL.
 */

/* Process RT scheduling */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "psched.h"
#include "die.h"

static inline const char *next_token(const char *q, int sep)
{
	if (q)
		q = strchr(q, sep);
	if (q)
		q++;

	return (q);
}

int set_cpu_affinity(const char *str, int inverted)
{
	int ret, i, cpus;
	const char *p, *q;
	cpu_set_t cpu_bitmask;

	q = str;
	cpus = sysconf(_SC_NPROCESSORS_CONF);
	CPU_ZERO(&cpu_bitmask);

	for (i = 0; inverted && i < cpus; ++i)
		CPU_SET(i, &cpu_bitmask);

	while (p = q, q = next_token(q, ','), p) {
		unsigned int a;	 /* Beginning of range */
		unsigned int b;	 /* End of range */
		unsigned int s;	 /* Stride */
		const char *c1, *c2;

		if (sscanf(p, "%u", &a) < 1)
			return -EINVAL;

		b = a;
		s = 1;

		c1 = next_token(p, '-');
		c2 = next_token(p, ',');

		if (c1 != NULL && (c2 == NULL || c1 < c2)) {
			if (sscanf(c1, "%u", &b) < 1)
				return -EINVAL;
			c1 = next_token(c1, ':');
			if (c1 != NULL && (c2 == NULL || c1 < c2))
				if (sscanf(c1, "%u", &s) < 1)
					return -EINVAL;
		}

		if (!(a <= b))
			return -EINVAL;

		while (a <= b) {
			if (inverted)
				CPU_CLR(a, &cpu_bitmask);
			else
				CPU_SET(a, &cpu_bitmask);
			a += s;
		}
	}

	ret = sched_setaffinity(getpid(), sizeof(cpu_bitmask),
				&cpu_bitmask);
	if (ret)
		panic("Can't set this cpu affinity!\n");
	return 0;
}

char *get_cpu_affinity(char *cpu_string, size_t len)
{
	int ret, i, cpu;
	cpu_set_t cpu_bitmask;

	if (len != sysconf(_SC_NPROCESSORS_CONF) + 1)
		return NULL;
	CPU_ZERO(&cpu_bitmask);

	ret = sched_getaffinity(getpid(), sizeof(cpu_bitmask),
				&cpu_bitmask);
	if (ret) {
		whine("Can't fetch cpu affinity!\n");
		return NULL;
	}

	for (i = 0, cpu_string[len - 1] = 0; i < len - 1; ++i) {
		cpu = CPU_ISSET(i, &cpu_bitmask);
		cpu_string[i] = (cpu ? '1' : '0');
	}

	return cpu_string;
}

int set_proc_prio(int priority)
{
	/*
	 * setpriority() is clever, even if you put a nice value which 
	 * is out of range it corrects it to the closest valid nice value
	 */
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
		whine("Cannot determine scheduler prio limits!\n");
	else if (priority < min_prio)
		priority = min_prio;
	else if (priority > max_prio)
		priority = max_prio;

	memset(&sp, 0, sizeof(sp));
	sp.sched_priority = priority;

	ret = sched_setscheduler(getpid(), policy, &sp);
	if (ret) {
		whine("Cannot set scheduler policy!\n");
		return -EINVAL;
	}

	ret = sched_setparam(getpid(), &sp);
	if (ret) {
		whine("Cannot set scheduler prio!\n");
		return -EINVAL;
	}

	return 0;
}

