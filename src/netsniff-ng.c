/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4   \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l120 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com> and 
 *                           Emmanuel Roullit <emmanuel.roullit@googlemail.com>
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
 *
 * Note: Your kernel has to be compiled with CONFIG_PACKET_MMAP=y option in 
 *       order to use this.
 */

#include <netsniff-ng/hash.h>

#include <netsniff-ng/types.h>
#include <netsniff-ng/rx_ring.h>
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

	init_configuration(&sd);
	set_configuration(argc, argv, &sd);
	check_config(&sd);
	init_system(&sd, &sock, &rb, &pfd);
	fetch_packets(&sd, sock, rb, &pfd);
	cleanup_system(&sd, &sock, &rb);

	return 0;
}
