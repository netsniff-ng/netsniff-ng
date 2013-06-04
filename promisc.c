#include <string.h>

#include "promisc.h"
#include "xutils.h"

short enter_promiscuous_mode(char *ifname)
{
	short ifflags;

	if (!strncmp("any", ifname, strlen("any")))
		return 0;

	ifflags = device_get_flags(ifname);
	device_set_flags(ifname, ifflags | IFF_PROMISC);

	return ifflags;
}

void leave_promiscuous_mode(char *ifname, short oldflags)
{
	if (!strncmp("any", ifname, strlen("any")))
		return;

	device_set_flags(ifname, oldflags);
}
