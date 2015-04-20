/*
 * Subject to the GPL, version 2.
 */

#include "xmalloc.h"

struct panic_func {
	void *arg;
	void (*on_panic)(void *arg);
	struct panic_func *next;
};

static struct panic_func *panic_funcs;

void panic_func_add(void (*on_panic)(void *arg), void *arg)
{
	struct panic_func *handler = xmallocz(sizeof(*handler));

	handler->arg		= arg;
	handler->on_panic	= on_panic;
	handler->next		= panic_funcs;
	panic_funcs		= handler;
};

void call_on_panic_funcs(void)
{
	struct panic_func *it;

	for (it = panic_funcs; it; it = it->next)
		it->on_panic(it->arg);
}
