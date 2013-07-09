#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <linux/net_tstamp.h>
#include <linux/if_packet.h>
#include <linux/if.h>

#include "str.h"
#include "tstamping.h"

int set_sockopt_hwtimestamp(int sock, const char *dev)
{
	int timesource, ret;
	struct hwtstamp_config hwconfig;
	struct ifreq ifr;

	if (!strncmp("any", dev, strlen("any")))
		return -1;

	memset(&hwconfig, 0, sizeof(hwconfig));
	hwconfig.tx_type = HWTSTAMP_TX_OFF;
	hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
	ifr.ifr_data = &hwconfig;

	ret = ioctl(sock, SIOCSHWTSTAMP, &ifr);
	if (ret < 0)
		return -1;

	timesource = SOF_TIMESTAMPING_RAW_HARDWARE;

	return setsockopt(sock, SOL_PACKET, PACKET_TIMESTAMP, &timesource,
			  sizeof(timesource));
}
