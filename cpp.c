#include <stdio.h>
#include <libgen.h>

#include "str.h"
#include "xmalloc.h"

int cpp_exec(char *in_file, char *out_file, size_t out_len)
{
	char *tmp = xstrdup(in_file);
	char cmd[256], *base;
	int ret = 0;

	base = basename(tmp);

	slprintf(out_file, out_len, "/tmp/.tmp-%u-%s", rand(), base);
	slprintf(cmd, sizeof(cmd), "cpp -I" ETCDIRE_STRING " %s > %s",
		 in_file, out_file);

	if (system(cmd) != 0)
		ret = -1;

	xfree(tmp);
	return ret;
}
