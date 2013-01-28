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
#include "xutils.h"
#include "aslookup.h"
#include "xmalloc.h"
#include "built_in.h"

enum parser_state {
	STATE_AS,
	STATE_IP,
	STATE_BGP_PREFIX,
	STATE_CC,
	STATE_REGISTRY,
	STATE_ALLOCATED,
	STATE_AS_NAME,
};

static int ai_family = 0, ai_socktype = 0, ai_protocol = 0;
static struct sockaddr_storage ai_ss;

int aslookup_prepare(const char *server, const char *port)
{
	int ret, fd = -1, try = 1;
	struct addrinfo hints, *ahead, *ai;

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

		/* we know details for later connections, close for now */
		close(fd);
		break;
	}

	freeaddrinfo(ahead);

	return 0;
}

int aslookup(const char *lhost, struct asrecord *rec)
{
	char *buff;
	int ret, fd;
	size_t len = 1024;

	bug_on(strlen(lhost) + 8 >= len);

	fd = socket(ai_family, ai_socktype, ai_protocol);
	if (unlikely(fd < 0))
		panic("Cannot create socket!\n");

	ret = connect(fd, (struct sockaddr *) &ai_ss, sizeof(ai_ss));
	if (unlikely(ret < 0))
		panic("Cannot connect to AS server!\n");

	buff = xzmalloc(len);
	slprintf(buff, len, "-v -f %s\r\n", lhost);
	ret = write(fd, buff, strlen(buff));
	if (unlikely(ret < 0))
		panic("Cannot write to AS server!\n");

	memset(buff, 0, len);
	while ((ret = read(fd, buff, len)) > 0) {
		int i;
		enum parser_state state = STATE_AS;
		char *ptr, *ptr2;

		buff[len - 1] = 0;
		for (i = 0, ptr = skips(buff); i < len; ++i) {
			if (buff[i] == '|' && state == STATE_AS) {
				buff[i] = 0;
				ptr2 = &buff[i] - 1;

				while (*ptr2 == ' ' && ptr2 > ptr) {
					*ptr2 = 0;
					ptr2--;
				}

				strlcpy(rec->number, ptr, strlen(ptr) + 1);

				ptr = skips(&buff[i] + 1);
				state = STATE_IP;
			} else if (buff[i] == '|' && state == STATE_IP) {
				buff[i] = 0;
				ptr2 = &buff[i] - 1;

				while (*ptr2 == ' ' && ptr2 > ptr) {
					*ptr2 = 0;
					ptr2--;
				}

				strlcpy(rec->ip, ptr, strlen(ptr) + 1);

				ptr = skips(&buff[i] + 1);
				state = STATE_BGP_PREFIX;
			} else if (buff[i] == '|' &&
				   state == STATE_BGP_PREFIX) {
				buff[i] = 0;
				ptr2 = &buff[i] - 1;

				while (*ptr2 == ' ' && ptr2 > ptr) {
					*ptr2 = 0;
					ptr2--;
				}

				strlcpy(rec->prefix, ptr, strlen(ptr) + 1);

				ptr = skips(&buff[i] + 1);
				state = STATE_CC;
			} else if (buff[i] == '|' && state == STATE_CC) {
				buff[i] = 0;
				ptr2 = &buff[i] - 1;

				while (*ptr2 == ' ' && ptr2 > ptr) {
					*ptr2 = 0;
					ptr2--;
				}

				strlcpy(rec->country, ptr, strlen(ptr) + 1);

				ptr = skips(&buff[i] + 1);
				state = STATE_REGISTRY;
			} else if (buff[i] == '|' && state == STATE_REGISTRY) {
				buff[i] = 0;
				ptr2 = &buff[i] - 1;

				while (*ptr2 == ' ' && ptr2 > ptr) {
					*ptr2 = 0;
					ptr2--;
				}

				strlcpy(rec->registry, ptr, strlen(ptr) + 1);

				ptr = skips(&buff[i] + 1);
				state = STATE_ALLOCATED;
			} else if (buff[i] == '|' && state == STATE_ALLOCATED) {
				buff[i] = 0;
				ptr2 = &buff[i] - 1;

				while (*ptr2 == ' ' && ptr2 > ptr) {
					*ptr2 = 0;
					ptr2--;
				}

				strlcpy(rec->since, ptr, strlen(ptr) + 1);

				ptr = skips(&buff[i] + 1);
				state = 6;
			} else if (buff[i] == '\n' && state == STATE_AS_NAME) {
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
