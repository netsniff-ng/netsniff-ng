/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#define _BSD_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <assert.h>

#include "xsys.h"
#include "tprintf.h"
#include "die.h"

static char buffer[1024];
static size_t buffer_use = 0;
static pthread_spinlock_t buffer_lock;

static size_t lcount = 0;

size_t tprintf_get_free_count(void)
{
	size_t ret;
	pthread_spin_lock(&buffer_lock);
	ret = get_tty_size() - 5 - lcount;
	pthread_spin_unlock(&buffer_lock);
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
	assert(buffer_use == 0);
}

void tprintf_init(void)
{
	pthread_spin_init(&buffer_lock, PTHREAD_PROCESS_SHARED);
	memset(buffer, 0, sizeof(buffer));
}

void tprintf_cleanup(void)
{
	pthread_spin_lock(&buffer_lock);
	tprintf_flush();
	pthread_spin_unlock(&buffer_lock);
	pthread_spin_destroy(&buffer_lock);
}

void tprintf(char *msg, ...)
{
	int ret;
	va_list vl;

	va_start(vl, msg);
	pthread_spin_lock(&buffer_lock);

	ret = vsnprintf(buffer + buffer_use,
			sizeof(buffer) - buffer_use,
			msg, vl);
	if (ret < 0)
		/* Something screwed up! Unexpected. */
		goto out;

	if (ret >= sizeof(buffer) - buffer_use) {
		tprintf_flush();

		/* Rewrite the buffer */
		ret = vsnprintf(buffer + buffer_use,
				sizeof(buffer) - buffer_use,
				msg, vl);
		/* Again, we've failed! This shouldn't happen! So 
		 * switch to vfprintf temporarily :-( */
		if (ret >= sizeof(buffer) - buffer_use) {
			fprintf(stderr, "BUG (buffer too large) -->\n");
			vfprintf(stdout, msg, vl);
			fprintf(stderr, " <--\n");
			goto out;
		}
	}

	if (ret < sizeof(buffer) - buffer_use)
		buffer_use += ret;

out:
	pthread_spin_unlock(&buffer_lock);
	va_end(vl);
}
