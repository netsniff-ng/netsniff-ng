#ifndef CPUS_H
#define CPUS_H

#include <unistd.h>
#include "built_in.h"
#include "die.h"

static inline unsigned int get_number_cpus(void)
{
	int ret = sysconf(_SC_NPROCESSORS_CONF);

	if (unlikely(ret <= 0))
		panic("get_number_cpus error!\n");

	return ret;
}

static inline unsigned int get_number_cpus_online(void)
{
	int ret = sysconf(_SC_NPROCESSORS_ONLN);

	if (unlikely(ret <= 0))
		panic("get_number_cpus_online error!\n");

	return ret;
}

#endif /* CPUS_H */
