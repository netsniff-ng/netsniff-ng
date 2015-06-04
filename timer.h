#ifndef TIMER_H
#define TIMER_H

#include <sys/time.h>

extern void set_itimer_interval_value(struct itimerval *itimer, unsigned long sec,
				      unsigned long usec);

extern int get_user_hz(void);

#endif /* TIMER_H */
