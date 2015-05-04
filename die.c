/*
 * Subject to the GPL, version 2.
 */

#include "xmalloc.h"

struct panic_handler {
	void *arg;
	pid_t pid;
	bool is_enabled;
	void (*on_panic)(void *arg);
	struct panic_handler *next;
};

static struct panic_handler *panic_handlers;

void panic_handler_add(void (*on_panic)(void *arg), void *arg)
{
	struct panic_handler *handler = xmallocz(sizeof(*handler));

	handler->arg		= arg;
	handler->pid		= getpid();
	handler->is_enabled	= true;
	handler->on_panic	= on_panic;
	handler->next		= panic_handlers;
	panic_handlers		= handler;
};

void call_panic_handlers(void)
{
	struct panic_handler *it;
	pid_t pid = getpid();

	for (it = panic_handlers; it; it = it->next) {
		if (it->pid == pid && it->is_enabled) {
			it->is_enabled = false;
			it->on_panic(it->arg);
		}
	}
}
