#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>

#include "cpp.h"
#include "str.h"
#include "proc.h"
#include "xmalloc.h"

static size_t argv_len(char *const argv[])
{
	size_t len = 0;

	for (; argv && *argv; argv++)
		len++;

	return len;
}

int cpp_exec(char *in_file, char *out_file, size_t out_len, char *const argv[])
{
	size_t argc = 7 + argv_len(argv);
	char *tmp = xstrdup(in_file);
	char **cpp_argv;
	int fd, ret = -1;
	char *base;
	unsigned int i = 0;

	base = basename(tmp);
	slprintf(out_file, out_len, "/tmp/.tmp-XXXXXX-%s", base);
	fd = mkstemps(out_file, strlen(base) + 1);
	if (fd < 0)
		goto err;

	cpp_argv = xmalloc(argc * sizeof(char *));

	cpp_argv[i++] = "cpp";

	for (; argv && *argv; argv++, i++)
		cpp_argv[i] = *argv;

	cpp_argv[i++] = "-I";
	cpp_argv[i++] = ETCDIRE_STRING;
	cpp_argv[i++] = "-o";
	cpp_argv[i++] = out_file;
	cpp_argv[i++] = in_file;
	cpp_argv[i++] = NULL;

	ret = proc_exec("cpp", cpp_argv);
	close(fd);

	xfree(cpp_argv);
err:
	xfree(tmp);
	return ret;
}
