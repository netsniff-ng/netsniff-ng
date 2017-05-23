#ifndef PROC_H
#define PROC_H

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern void cpu_affinity(int cpu);
extern int set_proc_prio(int prio);
extern int set_sched_status(int policy, int priority);
extern ssize_t proc_get_cmdline(unsigned int pid, char *cmdline, size_t len);
extern int proc_exec(const char *proc, char *const argv[]);
extern int proc_find_by_inode(ino_t ino, char *cmdline, size_t len, pid_t *pid);
extern bool proc_exists(pid_t pid);

#endif /* PROC_H */
