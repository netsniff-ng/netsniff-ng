#ifndef TSTAMPING_H
#define TSTAMPING_H

#include "config.h"

#ifdef HAVE_HARDWARE_TIMESTAMPING
extern int set_sockopt_hwtimestamp(int sock, const char *dev);
#else
static inline int set_sockopt_hwtimestamp(int sock, const char *dev)
{
	return -1;
}
#endif

#endif /* TSTAMPING_H */
