#include <unistd.h>
#include <sys/types.h>

#include "privs.h"
#include "die.h"

void drop_privileges(bool enforce, uid_t uid, gid_t gid)
{
	if (enforce) {
		if (uid == getuid())
			panic("Uid cannot be the same as the current user!\n");
		if (gid == getgid())
			panic("Gid cannot be the same as the current user!\n");
	}
	if (setgid(gid) != 0)
		panic("Unable to drop group privileges: %s!\n", strerror(errno));
	if (setuid(uid) != 0)
		panic("Unable to drop user privileges: %s!\n", strerror(errno));
}
