#include <stdio.h>
#include <libgen.h>

#include "str.h"
#include "xmalloc.h"

int cpp_exec(char *in_file, char *out_file, size_t out_len)
{
	char cmd[256], *dir, *base;
	char *a = xstrdup(in_file);
	char *b = xstrdup(in_file);
	int ret = 0;

	dir = dirname(a);
	base = basename(b);

	slprintf(out_file, out_len, "%s/.tmp-%u-%s", dir, rand(), base);
	slprintf(cmd, sizeof(cmd), "cpp -I" ETCDIRE_STRING " %s > %s",
		 in_file, out_file);

	if (system(cmd) != 0)
		ret = -1;

	xfree(a);
	xfree(b);
	return ret;
}
