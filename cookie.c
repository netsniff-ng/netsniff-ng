#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "cookie.h"

static char const *priov[] = {
	[LOG_EMERG]	=	"EMERG:",
	[LOG_ALERT]	=	"ALERT:",
	[LOG_CRIT]	=	"CRIT:",
	[LOG_ERR]	=	"ERR:",
	[LOG_WARNING]	=	"WARNING:",
	[LOG_NOTICE]	=	"NOTICE:",
	[LOG_INFO]	=	"INFO:",
	[LOG_DEBUG]	=	"DEBUG:",
};

static ssize_t cookie_writer(void *cookie, char const *data, size_t leng)
{
	int prio = LOG_DEBUG, len;

	do {
		len = strlen(priov[prio]);
	} while (memcmp(data, priov[prio], len) && --prio >= 0);

	if (prio < 0) {
		prio = LOG_INFO;
	} else {
		data += len;
		leng -= len;
	}

	while (*data == ' ') {
		 ++data;
		--leng;
	}

	syslog(prio, "%.*s", (int) leng, data);

	return leng;
}

static cookie_io_functions_t cookie_log = {
	.write		=	cookie_writer,
};

void to_std_log(FILE **fp)
{
	setvbuf(*fp = fopencookie(NULL, "w", cookie_log), NULL, _IOLBF, 0);
}
