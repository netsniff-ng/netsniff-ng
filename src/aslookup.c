/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>

#include "die.h"
#include "xstring.h"
#include "aslookup.h"
#include "xmalloc.h"
#include "built_in.h"

static int ai_family = 0;
static int ai_socktype = 0;
static int ai_protocol = 0;
static struct sockaddr_storage ai_ss;

int aslookup_prepare(const char *server, const char *port)
{
	int ret, fd = -1, try = 1;
	struct addrinfo hints, *ahead, *ai;
	struct sockaddr_in6 *saddr6;

	bug_on(!server || !port);

	memset(&ai_ss, 0, sizeof(ai_ss));
	memset(&hints, 0, sizeof(hints));

	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICSERV;

	ret = getaddrinfo(server, port, &hints, &ahead);
	if (ret != 0) {
		whine("Cannot get address info!\n");
		return -EIO;
	}

	for (ai = ahead; ai != NULL && fd < 0; ai = ai->ai_next) {
		if (ai->ai_family == PF_INET6)
			saddr6 = (struct sockaddr_in6 *) ai->ai_addr;
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		ret = connect(fd, ai->ai_addr, ai->ai_addrlen);
		if (ret < 0) {
			whine("Cannot connect to remote, try %d: %s!\n",
			      try++, strerror(errno));
			close(fd);
			fd = -1;
			continue;
		}

		ai_family = ai->ai_family;
		ai_socktype = ai->ai_socktype;
		ai_protocol = ai->ai_protocol;
		memcpy(&ai_ss, ai->ai_addr, ai->ai_addrlen);

		close(fd);
		break;
	}

	freeaddrinfo(ahead);
	return 0;
}

int aslookup(const char *lhost, struct asrecord *rec)
{
	int ret, err, fd = -1;
	char *buff;
	size_t len = 1024;

	bug_on(strlen(lhost) + 8 >= len);

	fd = socket(ai_family, ai_socktype, ai_protocol);
	if (fd < 0)
		return -EIO;

	ret = connect(fd, (struct sockaddr *) &ai_ss, sizeof(ai_ss));
	if (ret < 0)
		return -EIO;

	buff = xzmalloc(len);
	slprintf(buff, len, "-v -f %s\r\n", lhost);

	err = write(fd, buff, strlen(buff));
	if (unlikely(err < 0)) {
		whine("Cannot write to socket!\n");
		close(fd);
		xfree(buff);
		return err;
	}

	memset(buff, 0, len);
	while ((err = read(fd, buff, len)) > 0) {
		int state = 0, i;
		char *ptr = skips(buff), *ptr2;

		for (i = 0; i < len; ++i) {
			if (buff[i] == '|' && state == 0) {
				buff[i] = 0;
				ptr2 = &buff[i] - 1;

				while (*ptr2 == ' ' && ptr2 > ptr) {
					*ptr2 = 0;
					ptr2--;
				}

				strlcpy(rec->number, ptr, strlen(ptr) + 1);
				ptr = skips(&buff[i] + 1);
				state = 1;
			} else if (buff[i] == '|' && state == 1) {
				buff[i] = 0;
				ptr2 = &buff[i] - 1;

				while (*ptr2 == ' ' && ptr2 > ptr) {
					*ptr2 = 0;
					ptr2--;
				}

				strlcpy(rec->ip, ptr, strlen(ptr) + 1);
				ptr = skips(&buff[i] + 1);
				state = 2;
			} else if (buff[i] == '|' && state == 2) {
				buff[i] = 0;
				ptr2 = &buff[i] - 1;

				while (*ptr2 == ' ' && ptr2 > ptr) {
					*ptr2 = 0;
					ptr2--;
				}

				strlcpy(rec->prefix, ptr, strlen(ptr) + 1);
				ptr = skips(&buff[i] + 1);
				state = 3;
			} else if (buff[i] == '|' && state == 3) {
				buff[i] = 0;
				ptr2 = &buff[i] - 1;

				while (*ptr2 == ' ' && ptr2 > ptr) {
					*ptr2 = 0;
					ptr2--;
				}

				strlcpy(rec->country, ptr, strlen(ptr) + 1);
				ptr = skips(&buff[i] + 1);
				state = 4;
			} else if (buff[i] == '|' && state == 4) {
				buff[i] = 0;
				ptr2 = &buff[i] - 1;

				while (*ptr2 == ' ' && ptr2 > ptr) {
					*ptr2 = 0;
					ptr2--;
				}

				strlcpy(rec->registry, ptr, strlen(ptr) + 1);
				ptr = skips(&buff[i] + 1);
				state = 5;
			} else if (buff[i] == '|' && state == 5) {
				buff[i] = 0;
				ptr2 = &buff[i] - 1;

				while (*ptr2 == ' ' && ptr2 > ptr) {
					*ptr2 = 0;
					ptr2--;
				}

				strlcpy(rec->since, ptr, strlen(ptr) + 1);
				ptr = skips(&buff[i] + 1);
				state = 6;
			} else if (buff[i] == '\n' && state == 6) {
				buff[i] = 0;
				ptr2 = &buff[i] - 1;

				while (*ptr2 == ' ' && ptr2 > ptr) {
					*ptr2 = 0;
					ptr2--;
				}

				strlcpy(rec->name, ptr, strlen(ptr) + 1);
				goto out;
			}
		}

		memset(buff, 0, len);
	}
out:
	close(fd);
	xfree(buff);
	return 0;
}
