#ifndef DEV_H
#define DEV_H

#include <sys/socket.h>
#include "built_in.h"

extern size_t device_mtu(const char *ifname);
extern int device_address(const char *ifname, int af, struct sockaddr_storage *ss);
extern int __device_ifindex(const char *ifname);
extern int device_hw_address(const char *ifname, uint8_t *addr, size_t len);
extern int device_ifindex(const char *ifname);
extern int device_type(const char *ifname);
extern short device_get_flags(const char *ifname);
extern void device_set_flags(const char *ifname, const short flags);
extern int device_up_and_running(const char *ifname);
extern u32 device_bitrate(const char *ifname);
extern short device_enter_promiscuous_mode(const char *ifname);
extern void device_leave_promiscuous_mode(const char *ifname, short oldflags);
extern const char *device_type2str(uint16_t type);
extern const char *device_addr2str(const unsigned char *addr, int alen, int type,
				   char *buf, int blen);
#endif /* DEV_H */
