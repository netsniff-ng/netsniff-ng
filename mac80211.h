/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef MAC80211_H
#define MAC80211_H

extern void enter_rfmon_mac80211(const char *device, char **mondev);
extern void leave_rfmon_mac80211(const char *device, const char *mondev);

#endif /* MAC80211_H */
