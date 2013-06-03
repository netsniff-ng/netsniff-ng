#ifndef CPUS_H
#define CPUS_H

#include <unistd.h>

static inline int get_number_cpus(void)
{
	return sysconf(_SC_NPROCESSORS_CONF);
}

static inline int get_number_cpus_online(void)
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

#endif /* CPUS_H */
