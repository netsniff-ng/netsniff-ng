/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#define _BSD_SOURCE
#include <stdio.h>
#include <stdarg.h>

#include "xsys.h"
#include "tprintf.h"
#include "die.h"
#include "locking.h"
#include "built_in.h"

static char buffer[1024];
static size_t buffer_use = 0;

static struct spinlock buffer_lock;
static size_t lcount = 0;

size_t tprintf_get_free_count(void)
{
	size_t ret;

	spinlock_lock(&buffer_lock);
	ret = get_tty_size() - 5 - lcount;
	spinlock_unlock(&buffer_lock);

	return ret;
}

/*
 * We want to print our stuff terminal aligned. Since we're printing packets
 * we're in slowpath anyways. If stdin/stdout are connected to a terminal 
 * then default size = 1024; else size = 4096.
 */
void tprintf_flush(void)
{
	char *ptr = buffer;
	size_t flush_len = get_tty_size() - 5;

	while (buffer_use-- > 0) {
		if (lcount == flush_len) {
			fputs("\n   ", stdout);
			lcount = 3;
			while (buffer_use > 0 && (*ptr == ' ' || 
			       *ptr == ',' || *ptr == '\n')) {
				buffer_use--;
				ptr++;
			}
		}

		if (*ptr == '\n') {
			flush_len = get_tty_size() - 5;
			lcount = -1;
		}

		/* Collect in stream buffer. */
		fputc(*ptr, stdout);
		ptr++;
		lcount++;
	}

	fflush(stdout);
	buffer_use++;

	bug_on(buffer_use > 0);
}

void tprintf_init(void)
{
	spinlock_init(&buffer_lock);
	memset(buffer, 0, sizeof(buffer));
}

void tprintf_cleanup(void)
{
	spinlock_lock(&buffer_lock);
	tprintf_flush();
	spinlock_unlock(&buffer_lock);
	spinlock_destroy(&buffer_lock);
}

void tprintf(char *msg, ...)
{
	int ret;
	ssize_t avail;
	va_list vl;

	spinlock_lock(&buffer_lock);
	avail = sizeof(buffer) - buffer_use;

	va_start(vl, msg);
	ret = vsnprintf(buffer + buffer_use, avail, msg, vl);
	va_end(vl);
	if (ret < 0)
		panic("vsnprintf screwed up in tprintf!\n");
	if (ret > sizeof(buffer))
		panic("No mem in tprintf left!\n");
	if (ret >= avail) {
		buffer[buffer_use] = 0;
		tprintf_flush();

		avail = sizeof(buffer) - buffer_use;
		va_start(vl, msg);
		ret = vsnprintf(buffer + buffer_use, avail, msg, vl);
		va_end(vl);
		if (ret < 0)
			panic("vsnprintf screwed up in tprintf!\n");
	}

	buffer_use += ret;
	spinlock_unlock(&buffer_lock);
}
