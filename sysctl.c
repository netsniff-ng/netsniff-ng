/*
 * sysctl - sysctl set/get helpers
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "built_in.h"
#include "sysctl.h"

int sysctl_set_int(const char *file, int value)
{
	char path[PATH_MAX];
	char str[64];
	ssize_t ret;
	int fd;

	strncpy(path, SYSCTL_PROC_PATH, PATH_MAX);
	strncat(path, file, PATH_MAX - sizeof(SYSCTL_PROC_PATH) - 1);

	fd = open(path, O_WRONLY);
	if (unlikely(fd < 0))
		return -1;

	ret = snprintf(str, 63, "%d", value);
	if (ret < 0) {
		close(fd);
		return -1;
	}

	ret = write(fd, str, strlen(str));

	close(fd);
	return ret <= 0 ? -1 : 0;
}

int sysctl_get_int(const char *file, int *value)
{
	char path[PATH_MAX];
	char str[64];
	ssize_t ret;
	int fd;

	strncpy(path, SYSCTL_PROC_PATH, PATH_MAX);
	strncat(path, file, PATH_MAX - sizeof(SYSCTL_PROC_PATH) - 1);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, str, sizeof(str));
	if (ret > 0) {
		*value = atoi(str);
		ret = 0;
	} else {
		ret = -1;
	}

	close(fd);
	return ret;
}
