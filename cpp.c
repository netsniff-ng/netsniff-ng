#include <stdio.h>
#include <libgen.h>

#include "str.h"
#include "proc.h"
#include "xmalloc.h"

int cpp_exec(char *in_file, char *out_file, size_t out_len)
{
	char *tmp = xstrdup(in_file);
	char *argv[7] = {
		"cpp",
		"-I", ETCDIRE_STRING,
		"-o", out_file,
		in_file,
		NULL,
	};
	int ret = 0;
	char *base;

	base = basename(tmp);
	slprintf(out_file, out_len, "/tmp/.tmp-%u-%s", rand(), base);

	if (proc_exec("cpp", argv))
		ret = -1;

	xfree(tmp);
	return ret;
}
