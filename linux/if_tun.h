#ifndef LINUX_IF_TUN_H
#define LINUX_IF_TUN_H
#define IFF_TUN    0x0001
#define IFF_TAP    0x0002
#define IFF_NO_PI  0x1000
#define TUNSETIFF  _IOW('T', 202, int)
#endif
