#ifndef MAC80211_H
#define MAC80211_H

#include "config.h"
#include "die.h"

#ifdef HAVE_LIBNL
extern void enter_rfmon_mac80211(const char *device, char **mondev);
extern void leave_rfmon_mac80211(const char *mondev);
#else
static inline void enter_rfmon_mac80211(const char *device, char **mondev)
{
    panic("No built-in libnl support!\n");
}

static inline void leave_rfmon_mac80211(const char *mondev)
{
}
#endif /* HAVE_LIBNL */

#endif /* MAC80211_H */
