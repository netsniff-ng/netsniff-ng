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

#define _GNU_SOURCE
#define _NETSNIFF_NG_SERVER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <netsniff-ng.h>

#include <sys/resource.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include "macros.h"
#include "version.h"

int send_qmsg(int q_id, struct netsniff_msg *msg, pid_t pid, int type, char *buff, size_t len)
{
	int rc;

	if (!msg || !buff || !len)
		return -EINVAL;
	if (len > sizeof(msg->buff))
		return -ENOMEM;

	msg->pid = pid;
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

int recv_qmsg_all(int q_id, struct netsniff_msg *msg)
{
	ssize_t rc;

	if (!msg)
		return -EINVAL;

	msg->pid = 0;

	rc = msgrcv(q_id, msg, sizeof(*msg), 0, 0);
	if (rc < 0) {
		perror("msgrcv");
		exit(EXIT_FAILURE);
	}

	if (rc != sizeof(*msg))
		return -EIO;

	return 0;
}

int init_qmsg(int identifier)
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

/**
 * start_server - Detached server thread for Daemon
 * @arg:         nullbuff
 */
static void *start_server(void *null)
{
	int rc;
	int q_in_id, q_out_id;

	struct netsniff_msg msg;

	q_in_id = init_qmsg('O');	/* Client: I */
	q_out_id = init_qmsg('I');	/* Client: O */

	while (1) {
		rc = recv_qmsg_all(q_in_id, &msg);
		if (rc != 0)
			continue;

		printf("Received msg:\n");
		printf("  PID:  %ld\n", (long int)msg.pid);
		printf("  Type: %d\n", msg.type);
		printf("  Buf:  %s\n", msg.buff);

		/* Process request ... */

		send_qmsg(q_out_id, &msg, msg.pid, msg.type + 1, msg.buff, MAX_SEGMENT_LEN);
	}

	pthread_exit(0);
}

/**
 * undaemonize - Undaemonizes the system daemon
 * @pidfile:    path to pidfile
 */
int undaemonize(const char *pidfile)
{
	assert(pidfile);
	unlink(pidfile);
	return (0);
}

/**
 * daemonize - Creates system daemon
 * @pidfile:  path to pidfile
 * @logfile:  path to logfile
 * @sockfile: path to unix domain socket inode
 */
int daemonize(const char *pidfile)
{
	int fd;
	int ret;
	int cpid_len;
	int bytes_written;

	char cpid[32] = { 0 };

	pthread_t tid;
	pthread_attr_t attr;

	assert(pidfile);

	fd = open(pidfile, O_RDONLY);
	if (fd > 0) {
		err("Daemon already started." "Kill daemon and delete pid file %s", pidfile);
		close(fd);
		exit(EXIT_FAILURE);
	}

	info("%s %s in running in daemon mode\n", PROGNAME_STRING, VERSION_STRING);

	/* We start from root and redirect all output to /dev/zero */
	if (daemon(0, 0) != 0) {
		err("Cannot daemonize process");
		close(fd);
		exit(EXIT_FAILURE);
	}

	cpid_len = snprintf(cpid, sizeof(cpid), "%d", getpid());

	fd = open(pidfile, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		err("Openening pidfile");
		exit(EXIT_FAILURE);
	}

	bytes_written = write(fd, cpid, cpid_len);
	if (bytes_written != cpid_len) {
		err("Write failed! Only wrote %i", bytes_written);
		close(fd);
		exit(EXIT_FAILURE);
	}

	close(fd);

	pthread_attr_init(&attr);
	pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);

	ret = pthread_create(&tid, NULL, start_server, NULL);
	if (ret < 0) {
		err("Cannot create thread");
		undaemonize(pidfile);
		exit(EXIT_FAILURE);
	}

	pthread_detach(tid);

	info("netsniff-ng daemon up and running.\n");
	return (0);
}
