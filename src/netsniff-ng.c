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

#include <netsniff-ng/types.h>
#include <netsniff-ng/rx_ring.h>
#include <netsniff-ng/tx_ring.h>
#include <netsniff-ng/config.h>
#include <netsniff-ng/bootstrap.h>

/**
 * main  - Main routine
 * @argc: number of args
 * @argv: arguments passed from tty
 */
int main(int argc, char **argv)
{
	int sock;
	ring_buff_t *rb;
	system_data_t sd = { 0 };
	struct pollfd pfd = { 0 };

	/*
	 * Parse user config
	 */

	init_configuration(&sd);
	set_configuration(argc, argv, &sd);
	check_config(&sd);

	/*
	 * Init netsniff-ng and do the job 
	 */

	init_system(&sd, &sock, &rb, &pfd);
	if (sd.mode == MODE_CAPTURE)
		fetch_packets(&sd, sock, rb, &pfd);
	else if (sd.mode == MODE_REPLAY)
		transmit_packets(&sd, sock, rb);
	cleanup_system(&sd, &sock, &rb);

	return 0;
}
