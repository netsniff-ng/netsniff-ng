#ifndef TIMER_H
#define TIMER_H

#include <sys/time.h>

extern void set_itimer_interval_value(struct itimerval *itimer, unsigned long sec,
				      unsigned long usec);

#endif /* TIMER_H */
