/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL.
 */

#ifndef SYSTEM_H
#define SYSTEM_H

#include <unistd.h>
#include <sched.h>
#include <sys/resource.h>

#define DEFAULT_SCHED_POLICY  SCHED_FIFO
#define DEFAULT_SCHED_PRIO    sched_get_priority_max(DEFAULT_SCHED_POLICY)
#define DEFAULT_PROCESS_PRIO  -20

#define NR_CPUS               sysconf(_SC_NPROCESSORS_CONF)
#define NR_CPUS_ON            sysconf(_SC_NPROCESSORS_ONLN)

extern int set_cpu_affinity(const char *str, int inverted);
extern char *get_cpu_affinity(char *cpu_string, size_t len);
extern int set_proc_prio(int prio);
extern int set_sched_status(int policy, int priority);
extern void check_for_root_maybe_die(void);

#endif /* SYSTEM_H */
