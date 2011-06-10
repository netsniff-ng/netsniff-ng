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

#include "die.h"

static int rport = 6666;
static char *rhost = "127.0.0.1";

int main(int argc, char **argv)
{
	int fd, ret;
	struct sockaddr_in saddr;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0)
		panic("Cannot create socket!\n");

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(rport);

	ret = inet_aton(rhost, &saddr.sin_addr);
	if (ret < 0)
		panic("Invalid remote address!\n");

	ret = connect(fd, (struct sockaddr *) &saddr, sizeof(saddr));
	if (ret < 0)
		panic("Cannot connect to remote!\n");

	while (1) {
		sleep(1);
		write(fd, "hello world!", strlen("hello world!") + 1);
	}

	close(fd);
	return 0;
}

