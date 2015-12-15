#ifndef PROC_H
#define PROC_H

#include <stdlib.h>

extern void cpu_affinity(int cpu);
extern int set_proc_prio(int prio);
extern int set_sched_status(int policy, int priority);
extern ssize_t proc_get_cmdline(unsigned int pid, char *cmdline, size_t len);
extern int proc_exec(const char *proc, char *const argv[]);

#endif /* PROC_H */
