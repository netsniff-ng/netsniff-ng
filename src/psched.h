/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#ifndef PSCHED_H
#define PSCHED_H

#include <unistd.h>
#include <sched.h>
#include <sys/resource.h>

extern int set_cpu_affinity(const char *str, int inverted);
extern char *get_cpu_affinity(char *cpu_string, size_t len);
extern int set_proc_prio(int prio);
extern int set_sched_status(int policy, int priority);

static inline int get_default_sched_policy(void)
{
	return SCHED_FIFO;
}

static inline int get_default_sched_prio(void)
{
	return sched_get_priority_max(get_default_sched_policy());
}

static inline int get_number_cpus(void)
{
	return sysconf(_SC_NPROCESSORS_CONF);
}

static inline int get_number_cpus_online(void)
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

static inline int get_default_proc_prio(void)
{
	return -20;
}

#endif /* PSCHED_H */
