/*
 * netsniff-ng - the packet sniffing beast
 * libtap (Write tests in C, by Jake Gelbman)
 * Copyright 2012 Jake Gelbman <gelbman@gmail.com>
 * Copyright 2012 Daniel Borkmann <borkmann@iogearbox.net>
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <regex.h>

#include "tap.h"
#include "../die.h"
#include "../xmalloc.h"
#include "../tprintf.h"

static int expected_tests = NO_PLAN, failed_tests, current_test;
static char *todo_mesg;

static char *vstrdupf(const char *fmt, va_list args)
{
	char *str;
	int size;
	va_list args2;

	va_copy(args2, args);
	if (!fmt)
		fmt = "";

	size = vsnprintf(NULL, 0, fmt, args2) + 2;
	str = xmalloc(size);

	vsprintf(str, fmt, args);
	va_end(args2);

	return str;
}

void cplan(int tests, const char *fmt, ...)
{
	expected_tests = tests;

	if (tests == SKIP_ALL) {
		char *why;
		va_list args;

		va_start(args, fmt);
		why = vstrdupf(fmt, args);
		va_end(args);

		printf("1..0 ");
		note("SKIP %s\n", why);

		die();
	}

	if (tests != NO_PLAN)
		printf("1..%d\n", tests);
}

int vok_at_loc(const char *file, int line, int test, const char *fmt,
	       va_list args)
{
	char *name = vstrdupf(fmt, args);

	printf("%sok %d", test ? colorize_start(green) colorize_start(bold) :
	       colorize_start(red) colorize_start(bold) "not ", ++current_test);

	if (*name)
		printf(" - %s", name);
	if (todo_mesg) {
		printf(" # TODO");
		if (*todo_mesg)
			printf(" %s", todo_mesg);
	}

	printf("%s\n", colorize_end());

	if (!test) {
		if (*name)
			diag("  %sFailed%s test '%s'\n  at %s line %d.%s",
			     colorize_start(red), todo_mesg ? " (TODO)" : "",
			     name, file, line, colorize_end());
		else
			diag("  %sFailed%s test at %s line %d.%s",
			     colorize_start(red), todo_mesg ? " (TODO)" : "",
			     file, line, colorize_end());
		if (!todo_mesg)
			failed_tests++;
	}

	xfree(name);
	return test;
}

int ok_at_loc(const char *file, int line, int test, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vok_at_loc(file, line, test, fmt, args);
	va_end(args);

	return test;
}

static inline int mystrcmp (const char *a, const char *b)
{
    return a == b ? 0 : !a ? -1 : !b ? 1 : strcmp(a, b);
}

#define eq(a, b)	(!mystrcmp(a, b))
#define ne(a, b)	(mystrcmp(a, b))

int is_at_loc(const char *file, int line, const char *got, const char *expected,
	      const char *fmt, ...)
{
	int test = eq(got, expected);
	va_list args;

	va_start(args, fmt);
	vok_at_loc(file, line, test, fmt, args);
	va_end(args);

	if (!test) {
		diag("         %sgot: '%s'", colorize_start(red), got);
		diag("    expected: '%s'%s", expected, colorize_end());
	}

	return test;
}

int isnt_at_loc(const char *file, int line, const char *got,
		const char *expected, const char *fmt, ...)
{
	int test = ne(got, expected);
	va_list args;

	va_start(args, fmt);
	vok_at_loc(file, line, test, fmt, args);
	va_end(args);

	if (!test) {
		diag("         %sgot: '%s'", colorize_start(red), got);
		diag("    expected: anything else%s", colorize_end());
	}

	return test;
}

int cmp_ok_at_loc(const char *file, int line, int a, const char *op, int b,
		  const char *fmt, ...)
{
	va_list args;
	int test = eq(op, "||") ? a || b
		 : eq(op, "&&") ? a && b
		 : eq(op, "|")  ? a |  b
		 : eq(op, "^")  ? a ^  b
		 : eq(op, "&")  ? a &  b
		 : eq(op, "==") ? a == b
		 : eq(op, "!=") ? a != b
		 : eq(op, "<")  ? a <  b
		 : eq(op, ">")  ? a >  b
		 : eq(op, "<=") ? a <= b
		 : eq(op, ">=") ? a >= b
		 : eq(op, "<<") ? a << b
		 : eq(op, ">>") ? a >> b
		 : eq(op, "+")  ? a +  b
		 : eq(op, "-")  ? a -  b
		 : eq(op, "*")  ? a *  b
		 : eq(op, "/")  ? a /  b
		 : eq(op, "%")  ? a %  b
		 : diag("unrecognized operator '%s'", op);

	va_start(args, fmt);
	vok_at_loc(file, line, test, fmt, args);
	va_end(args);

	if (!test) {
		diag("    %s%d", colorize_start(red), a);
		diag("        %s", op);
		diag("    %d%s", b, colorize_end());
	}

	return test;
}

static void vdiag_to_fh(FILE *fh, const char *fmt, va_list args)
{
	int i;
	char *mesg, *line;

	if (!fmt)
		return;

	mesg = vstrdupf(fmt, args);
	line = mesg;

	for (i = 0; *line; i++) {
		char c = mesg[i];
		if (!c || c == '\n') {
			mesg[i] = '\0';
			fprintf(fh, "%s# %s%s\n", colorize_start(red),
				line, colorize_end());
			if (!c)
				break;
			mesg[i] = c;
			line = mesg + i + 1;
		}
	}

	xfree(mesg);
	return;
}

int diag(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vdiag_to_fh(stderr, fmt, args);
	va_end(args);

	return 0;
}

int note(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vdiag_to_fh(stdout, fmt, args);
	va_end(args);

	return 0;
}

int exit_status(void)
{
	int retval = 0;

	if (expected_tests == NO_PLAN) {
		printf("1..%d\n", current_test);
	} else if (current_test != expected_tests) {
		diag("Looks like you planned %d test%s but ran %d.",
		     expected_tests, expected_tests > 1 ? "s" : "",
		     current_test);

		retval = 255;
	}

	if (failed_tests) {
		diag("Looks like you failed %d test%s of %d run.",
		     failed_tests, failed_tests > 1 ? "s" : "",
		     current_test);

		if (expected_tests == NO_PLAN)
			retval = failed_tests;
		else
			retval = expected_tests - current_test + failed_tests;
	}

	return retval;
}

int bail_out(int ignore, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	printf("Bail out!  ");
	vprintf(fmt, args);
	printf("\n");
	va_end(args);

	exit(255);
	return 0;
}

void skippy(int n, const char *fmt, ...)
{
	char *why;
	va_list args;

	va_start(args, fmt);
	why = vstrdupf(fmt, args);
	va_end(args);

	while (n --> 0) {
		printf("ok %d ", ++current_test);
		note("skip %s\n", why);
	}

	xfree(why);
}

void ctodo(int ignore, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	todo_mesg = vstrdupf(fmt, args);
	va_end(args);
}

void cendtodo(void)
{
	xfree(todo_mesg);
	todo_mesg = NULL;
}

/* Create a shared memory int to keep track of whether a piece of code
 * executed dies. to be used in the dies_ok and lives_ok macros */
int tap_test_died(int status)
{
	int prev;
	static int *test_died = NULL;

	if (!test_died) {
		test_died = mmap(0, sizeof (int), PROT_READ | PROT_WRITE,
				 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		*test_died = 0;
	}

	prev = *test_died;
	*test_died = status;

	return prev;
}

int like_at_loc(int for_match, const char *file, int line, const char *got,
		const char *expected, const char *fmt, ...)
{
	int test, err;
	regex_t re;
	va_list args;

	err = regcomp(&re, expected, REG_EXTENDED);
	if (err) {
		char errbuf[256];
		regerror(err, &re, errbuf, sizeof errbuf);
		fprintf(stderr, "Unable to compile regex '%s': %s "
			"at %s line %d\n", expected, errbuf, file, line);
		exit(255);
	}

	err = regexec(&re, got, 0, NULL, 0);
	regfree(&re);

	test = for_match ? !err : err;

	va_start(args, fmt);
	vok_at_loc(file, line, test, fmt, args);
	va_end(args);

	if (!test) {
		if (for_match) {
			diag("                   '%s'", got);
			diag("    doesn't match: '%s'", expected);
		} else {
			diag("                   '%s'", got);
			diag("          matches: '%s'", expected);
		}
	}

	return test;
}
