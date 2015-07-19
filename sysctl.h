#ifndef SYSCTL_H
#define SYSCTL_H

int sysctl_set_int(const char *file, int value);
int sysctl_get_int(const char *file, int *value);

#endif
