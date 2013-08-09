#ifndef PROMISC_H
#define PROMISC_H

extern short enter_promiscuous_mode(const char *ifname);
extern void leave_promiscuous_mode(const char *ifname, short oldflags);

#endif /* PROMISC_H */
