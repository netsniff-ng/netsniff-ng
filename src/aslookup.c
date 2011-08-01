/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>

#include "die.h"
#include "strlcpy.h"
#include "parser.h"
#include "aslookup.h"

/* e.g., aslookup("8.8.8.8", &rec, "whois.cymru.com", "43"); */

int aslookup(char *lhost, struct asrecord *rec, char *server, char *port)
{
	int ret, err, fd = -1, try = 1;
	struct addrinfo hints, *ahead, *ai;
	struct sockaddr_in6 *saddr6;
	char buff[1024];

	if (!lhost || strlen(lhost) + 8 > sizeof(buff) || !rec ||
	    !server || !port)
		return -EIO;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	ret = getaddrinfo(server, port, &hints, &ahead);
	if (ret < 0) {
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
	}

	freeaddrinfo(ahead);
	if (fd < 0) {
		whine("Cannot create socket!\n");
		return -EIO;
	}

	memset(buff, 0, sizeof(buff));
	slprintf(buff, sizeof(buff), "-v -f %s\r\n", lhost);

	err = write(fd, buff, strlen(buff));
	if (unlikely(err < 0)) {
		whine("Cannot write to socket!\n");
		close(fd);
		return err;
	}

	memset(buff, 0, sizeof(buff));
	while ((err = read(fd, buff, sizeof(buff))) > 0) {
		int state = 0, i;
		char *ptr = skips(buff), *ptr2;
		for (i = 0; i < sizeof(buff); ++i) {
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
		memset(buff, 0, sizeof(buff));
	}
out:
	close(fd);
	return 0;
}

