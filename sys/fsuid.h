/*
 * sys/fsuid.h - macOS stub for Linux filesystem UID calls
 */
#ifndef SYS_FSUID_H
#define SYS_FSUID_H

#include <unistd.h>

static inline int setfsuid(uid_t uid) { return (int)setuid(uid); }
static inline int setfsgid(gid_t gid) { return (int)setgid(gid); }

#endif /* SYS_FSUID_H */
