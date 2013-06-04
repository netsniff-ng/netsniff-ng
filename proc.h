#ifndef PROC_H
#define PROC_H

extern void cpu_affinity(int cpu);
extern int set_proc_prio(int prio);
extern int set_sched_status(int policy, int priority);

#endif /* PROC_H */
