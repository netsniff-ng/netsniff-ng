#ifndef MAC80211_H
#define MAC80211_H

extern void enter_rfmon_mac80211(const char *device, char **mondev);
extern void leave_rfmon_mac80211(const char *mondev);

#endif /* MAC80211_H */
