#ifndef PRIVS_H
#define PRIVS_H

#include <stdbool.h>

extern void drop_privileges(bool enforce, uid_t uid, gid_t gid);

#endif /* PRIVS_H */
