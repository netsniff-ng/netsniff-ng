#ifndef LINK_H
#define LINK_H

#include <stdint.h>
#include <sys/socket.h>
#include <linux/ethtool.h>
#include <linux/wireless.h>

#ifndef SPEED_UNKNOWN
#define SPEED_UNKNOWN           -1
#endif

#include "built_in.h"

extern int wireless_sigqual(const char *ifname, struct iw_statistics *stats);
extern int wireless_rangemax_sigqual(const char *ifname);
extern uint32_t wireless_bitrate(const char *ifname);
extern uint32_t ethtool_bitrate(const char *ifname);
extern int ethtool_drvinf(const char *ifname, struct ethtool_drvinfo *drvinf);
extern int ethtool_link(const char *ifname);

#endif /* LINK_H */
