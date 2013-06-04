#include <stdio.h>
#include <signal.h>

#include "sig.h"

void register_signal(int signal, void (*handler)(int))
{
	sigset_t block_mask;
	struct sigaction saction;

	sigfillset(&block_mask);

	saction.sa_handler = handler;
	saction.sa_mask = block_mask;
	saction.sa_flags = SA_RESTART;

	sigaction(signal, &saction, NULL);
}

void register_signal_f(int signal, void (*handler)(int), int flags)
{
	sigset_t block_mask;
	struct sigaction saction;

	sigfillset(&block_mask);

	saction.sa_handler = handler;
	saction.sa_mask = block_mask;
	saction.sa_flags = flags;

	sigaction(signal, &saction, NULL);
}
