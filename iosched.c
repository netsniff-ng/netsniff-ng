/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2010 Marek Polacek.
 * Subject to the GPL, version 2.
 */

#include <sys/syscall.h>

#include "iosched.h"
#include "die.h"

#define IOPRIO_CLASS_SHIFT      13

enum {
	ioprio_class_none,
	ioprio_class_rt,
	ioprio_class_be,
	ioprio_class_idle,
};

enum {
	ioprio_who_process = 1,
	ioprio_who_pgrp,
	ioprio_who_user,
};

static const char *const to_prio[] = {
	"none",
	"realtime",
	"best-effort",
	"idle",
};

static inline int ioprio_set(int which, int who, int ioprio)
{
	return syscall(SYS_ioprio_set, which, who, ioprio);
}

static inline int ioprio_get(int which, int who)
{
	return syscall(SYS_ioprio_get, which, who);
}

static void ioprio_setpid(pid_t pid, int ioprio, int ioclass)
{
	int ret = ioprio_set(ioprio_who_process, pid,
			     ioprio | ioclass << IOPRIO_CLASS_SHIFT);
	if (ret < 0)
		panic("Failed to set io prio for pid!\n");
}

void ioprio_print(void)
{
	int ioprio = ioprio_get(ioprio_who_process, getpid());
	if (ioprio < 0)
		panic("Failed to fetch io prio for pid!\n");
	else {
		int ioclass = ioprio >> IOPRIO_CLASS_SHIFT;
		if (ioclass != ioprio_class_idle) {
			ioprio &= 0xff;
			printf("%s: prio %d\n", to_prio[ioclass], ioprio);
		} else
			printf("%s\n", to_prio[ioclass]);
	}
}

void set_ioprio_rt(void)
{
	ioprio_setpid(getpid(), 4, ioprio_class_rt);
}

void set_ioprio_be(void)
{
	ioprio_setpid(getpid(), 4, ioprio_class_be);
}
