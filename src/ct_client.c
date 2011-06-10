/*
 * curvetun - the cipherspace wormhole creator
 * Part of the netsniff-ng project
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann <daniel@netsniff-ng.org>,
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>

#include "die.h"

static const char *rport = "6666";
static const char *rhost = "localhost";
static const char *scope = "eth10";

int main(int argc, char **argv)
{
	int fd = -1, ret;
	struct addrinfo hints, *ahead, *ai;
	struct sockaddr_in6 *saddr6;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	ret = getaddrinfo(rhost, rport, &hints, &ahead);
	if (ret < 0)
		panic("Cannot get address info!\n");

	for (ai = ahead; ai != NULL && fd < 0; ai = ai->ai_next) {
		if (ai->ai_family == PF_INET6) {
			saddr6 = (struct sockaddr_in6 *) ai->ai_addr;
			if (saddr6->sin6_scope_id == 0)
				saddr6->sin6_scope_id = if_nametoindex(scope);
		}

		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;

		ret = connect(fd, ai->ai_addr, ai->ai_addrlen);
		if (ret < 0) {
			close(fd);
			fd = -1;
			continue;
		}
	}

	freeaddrinfo(ahead);
	if (fd < 0)
		panic("Cannot create socket!\n");

	while (1) {
		sleep(1);
		ret = write(fd, "hello world!", strlen("hello world!") + 1);
		if (ret != strlen("hello world!") + 1)
			perror("write");
	}

	close(fd);
	return 0;
}

