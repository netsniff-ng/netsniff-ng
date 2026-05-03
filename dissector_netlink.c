/*
 * dissector_netlink.c - stubbed for macOS BPF port
 * Original used linux/netlink.h which doesn't exist on Darwin
 */
#include "dissector_netlink.h"

void dissector_init_netlink(int fnttype) { (void)fnttype; }
void dissector_cleanup_netlink(void) {}
