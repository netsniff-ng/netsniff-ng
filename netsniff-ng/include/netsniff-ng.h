/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 */

/* External IPC API */

#ifndef _NETSNIFF_NG_H_
#define _NETSNIFF_NG_H_

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define MAX_SEGMENT_LEN 16

struct netsniff_msg {
	pid_t pid;		/* Programs process id */
	int type;		/* Message type */
	char buff[MAX_SEGMENT_LEN];	/* Message buffer */
};

/* Some simple provided IPC calls for client implementations */

#ifndef _NETSNIFF_NG_SERVER
# define init_receive_qmsg()         init_qmsg('I')
# define init_send_qmsg()            init_qmsg('O')

static inline int send_qmsg(int q_id, struct netsniff_msg *msg, int type, char *buff, size_t len)
{
	int rc;

	if (!msg || !buff || !len)
		return -EINVAL;
	if (len > sizeof(msg->buff))
		return -ENOMEM;

	msg->pid = getpid();
	msg->type = type;

	memcpy(msg->buff, buff, len);
	memset(msg->buff + len, 0, sizeof(msg->buff) - len);

	rc = msgsnd(q_id, msg, sizeof(*msg), 0);
	if (rc != 0) {
		perror("msgsnd");
		exit(EXIT_FAILURE);
	}

	return 0;
}

static inline int recv_qmsg(int q_id, struct netsniff_msg *msg)
{
	ssize_t rc;

	if (!msg)
		return -EINVAL;

	msg->pid = getpid();

	rc = msgrcv(q_id, msg, sizeof(*msg), 0, 0);
	if (rc < 0) {
		perror("msgrcv");
		exit(EXIT_FAILURE);
	}

	if (rc != sizeof(*msg))
		return -EIO;

	return 0;
}

static inline int init_qmsg(int identifier)
{
	int q_id;
	key_t q_key;

	q_key = ftok("/dev/random", identifier);

	q_id = msgget(q_key, IPC_CREAT | 0660);
	if (q_id < 0) {
		perror("msgget");
		exit(EXIT_FAILURE);
	}

	return q_id;
}
#endif				/* _NETSNIFF_NG_SERVER */
#endif				/* _NETSNIFF_NG_H_ */
