#ifndef DEV_H
#define DEV_H

#include <sys/socket.h>
#include "built_in.h"

extern int device_mtu(const char *ifname);
extern int device_address(const char *ifname, int af, struct sockaddr_storage *ss);
extern int device_ifindex(const char *ifname);
extern short device_get_flags(const char *ifname);
extern void device_set_flags(const char *ifname, const short flags);
extern int device_up_and_running(char *ifname);
extern u32 device_bitrate(const char *ifname);

#endif /* DEV_H */
