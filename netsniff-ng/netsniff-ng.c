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
#include <netsniff-ng/read.h>
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
	struct ring_buff *rb;
	struct system_data sd = { 0 };

	init_configuration(&sd);
	set_configuration(argc, argv, &sd);
	check_config(&sd);

	init_system(&sd, &sock, &rb);

	switch (sd.mode) {
	case MODE_CAPTURE:
		fetch_packets(&sd, sock, rb);
		break;
	case MODE_REPLAY:
		transmit_packets(&sd, sock, rb);
		break;
	case MODE_READ:
		display_packets(&sd);
		break;
	default:
		break;
	};

	cleanup_system(&sd, &sock, &rb);

	return 0;
}
