#ifndef SYSCTL_H
#define SYSCTL_H

#define SYSCTL_PROC_PATH "/proc/sys/"

int sysctl_set_int(const char *file, int value);
int sysctl_get_int(const char *file, int *value);

#endif
