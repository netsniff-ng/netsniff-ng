#include <sys/time.h>

#include "timer.h"

void set_itimer_interval_value(struct itimerval *itimer, unsigned long sec,
			       unsigned long usec)
{
	itimer->it_interval.tv_sec = sec;
	itimer->it_interval.tv_usec = usec;

	itimer->it_value.tv_sec = sec;
	itimer->it_value.tv_usec = usec;
}
