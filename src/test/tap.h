/*
 * netsniff-ng - the packet sniffing beast
 * libtap (Write tests in C, by Jake Gelbman)
 * Copyright 2012 Jake Gelbman <gelbman@gmail.com>
 * Copyright 2012 Daniel Borkmann <borkmann@iogearbox.net>
 * Subject to the GPL, version 2.
 */

#ifndef TAP_H
#define TAP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../die.h"
#include "../tprintf.h"

extern int vok_at_loc(const char *file, int line, int test, const char *fmt,
		      va_list args);
extern int ok_at_loc(const char *file, int line, int test, const char *fmt,
		     ...);
extern int is_at_loc(const char *file, int line, const char *got,
		     const char *expected, const char *fmt, ...);
extern int isnt_at_loc(const char *file, int line, const char *got,
                         const char *expected, const char *fmt, ...);
extern int cmp_ok_at_loc(const char *file, int line, int a, const char *op,
                         int b, const char *fmt, ...);
extern int bail_out(int ignore, const char *fmt, ...);
extern void cplan(int tests, const char *fmt, ...);
extern int diag(const char *fmt, ...);
extern int note(const char *fmt, ...);
extern int exit_status(void);
extern void skippy(int n, const char *fmt, ...);
extern void ctodo(int ignore, const char *fmt, ...);
extern void cendtodo(void);

#define NO_PLAN		-1
#define SKIP_ALL	-2

#define ok(...)		ok_at_loc(__FILE__, __LINE__, __VA_ARGS__, NULL)
#define is(...)		is_at_loc(__FILE__, __LINE__, __VA_ARGS__, NULL)
#define isnt(...)	isnt_at_loc(__FILE__, __LINE__, __VA_ARGS__, NULL)
#define cmp_ok(...)	cmp_ok_at_loc(__FILE__, __LINE__, __VA_ARGS__, NULL)

#define plan(...)	cplan(__VA_ARGS__, NULL)
#define done_testing()	return exit_status()
#define BAIL_OUT(...)	bail_out(0, "" __VA_ARGS__, NULL)

#define pass(...)	ok(1, "" __VA_ARGS__)
#define fail(...)	ok(0, "" __VA_ARGS__)

#define skip(test, ...)	do { if (test) { skippy(__VA_ARGS__, NULL); break; }
#define endskip		} while (0)

#define todo(...)	ctodo(0, "" __VA_ARGS__, NULL)
#define endtodo		cendtodo()

#define dies_ok(...)	dies_ok_common(1, __VA_ARGS__)
#define lives_ok(...)	dies_ok_common(0, __VA_ARGS__)

#define like(...)	like_at_loc(1, __FILE__, __LINE__, __VA_ARGS__, NULL)
#define unlike(...)	like_at_loc(0, __FILE__, __LINE__, __VA_ARGS__, NULL)

extern int like_at_loc(int for_match, const char *file, int line,
		       const char *got, const char *expected,
		       const char *fmt, ...);
extern int tap_test_died (int status);

#define dies_ok_common(for_death, code, ...)		\
	do {						\
		int cpid;				\
		int it_died;				\
							\
		tap_test_died(1);			\
		cpid = fork();				\
							\
		switch (cpid) {				\
		case -1:				\
			panic("fork error!\n");		\
		case 0:					\
			close(1);			\
			close(2);			\
			{code}				\
			tap_test_died(0);		\
			die();				\
		}					\
							\
		if (waitpid(cpid, NULL, 0) < 0)		\
			panic("waitpid error!\n");	\
							\
		it_died = tap_test_died(0);		\
		if (!it_died)				\
			{code}				\
							\
		ok(for_death ? it_died :		\
			      !it_died, "" __VA_ARGS__);\
	} while (0)

#endif /* TAP_H */
