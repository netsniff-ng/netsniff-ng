#
# netsniff-ng - the packet sniffing beast
# By Daniel Borkmann <daniel@netsniff-ng.org>
# Copyright 2012 Daniel Borkmann <daniel@netsniff-ng.org>.
# Subject to the GPL, version 2.
#

include(CheckCSourceRuns)

check_c_source_runs("
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/net_tstamp.h>

static inline void set_sockopt_hwtimestamp(int sock, const char *dev)
{
	int timesource, ret;
	struct hwtstamp_config hwconfig;
	struct ifreq ifr;

	memset(&hwconfig, 0, sizeof(hwconfig));
	hwconfig.tx_type = HWTSTAMP_TX_ON;
	hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
	ifr.ifr_data = &hwconfig;

	ret = ioctl(sock, SIOCSHWTSTAMP, &ifr);
	if (ret < 0)
		exit(3);

	timesource = SOF_TIMESTAMPING_RAW_HARDWARE;

	ret = setsockopt(sock, SOL_PACKET, PACKET_TIMESTAMP, &timesource,
			 sizeof(timesource));
	if (ret)
		exit(3);
}

int main(int argc, char *argv[])
{
	int sock;

	set_sockopt_hwtimestamp(sock, "eth0");

	exit(0);
}" HWTSTAMP_RUN_RESULT)

set(HAVE_HWTSTAMP NO)

if(HWTSTAMP_RUN_RESULT EQUAL 1)
  set(HAVE_HWTSTAMP YES)
  message(STATUS "System has SOF_TIMESTAMPING_RAW_HARDWARE support")
else(HWTSTAMP_RUN_RESULT EQUAL 1)
  message(STATUS "System has no SOF_TIMESTAMPING_RAW_HARDWARE support")
endif(HWTSTAMP_RUN_RESULT EQUAL 1)
