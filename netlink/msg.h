#ifndef NETLINK_MSG_H
#define NETLINK_MSG_H
#include "linux_compat.h"
static inline void *nlmsg_data(struct nlmsghdr *h) {
    return (void *)((char *)h + sizeof(struct nlmsghdr));
}
#endif
