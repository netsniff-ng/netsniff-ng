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

/*
 * Contains: 
 *    Mostly RX_RING related stuff and other networking code
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/types.h>
#include <netsniff-ng/rx_ring.h>
#include <netsniff-ng/netdev.h>

/**
 * destroy_virt_rx_ring - Destroys virtual RX_RING buffer
 * @sock:                socket
 * @rb:                  ring buffer
 */
void destroy_virt_rx_ring(int sock, ring_buff_t * rb)
{
	assert(rb);

	memset(&(rb->layout), 0, sizeof(rb->layout));
	setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (void *)&(rb->layout), sizeof(rb->layout));

	if (rb->buffer) {
		munmap(rb, rb->len);
		rb->buffer = 0;
		rb->len = 0;
	}

	free(rb->frames);
}

/**
 * create_virt_rx_ring - Creates virtual RX_RING buffer
 * @sock:               socket
 * @rb:                 ring buffer
 */
void create_virt_rx_ring(int sock, ring_buff_t * rb, char *ifname)
{
	short nic_flags;
	int ret, dev_speed;

	assert(rb);

	nic_flags = get_nic_flags(ifname);

	if (!(nic_flags & IFF_UP)) {
		info("The interface %s is not up\n\n", ifname);
		exit(EXIT_FAILURE);
	}

	if (!(nic_flags & IFF_RUNNING)) {
		info("The interface %s is not running\n\n", ifname);
		exit(EXIT_FAILURE);
	}

	dev_speed = get_device_bitrate_generic_fallback(ifname) >> 3;
	memset(&(rb->layout), 0, sizeof(rb->layout));

	/* max: getpagesize() << 11 for i386 */
	rb->layout.tp_block_size = getpagesize() << 2;
	rb->layout.tp_frame_size = TPACKET_ALIGNMENT << 7;

	/* max: 15 for i386, old default: 1 << 13, now: approximated bandwidth size */
	rb->layout.tp_block_nr = (dev_speed * 1100000) / rb->layout.tp_block_size;
	rb->layout.tp_frame_nr = rb->layout.tp_block_size / rb->layout.tp_frame_size * rb->layout.tp_block_nr;

 __retry_sso:
	ret = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (void *)&(rb->layout), sizeof(rb->layout));

	if (errno == ENOMEM && rb->layout.tp_block_nr > 1) {
		rb->layout.tp_block_nr >>= 1;
		rb->layout.tp_frame_nr = rb->layout.tp_block_size / rb->layout.tp_frame_size * rb->layout.tp_block_nr;

		goto __retry_sso;
	}

	if (ret < 0) {
		perr("setsockopt: creation of rx ring failed: %d - ", errno);

		close(sock);
		exit(EXIT_FAILURE);
	}

	rb->len = rb->layout.tp_block_size * rb->layout.tp_block_nr;

	info("%.2f MB allocated for rx ring \n", 1.f * rb->len / (1024 * 1024));
	info(" [ %d blocks, %d frames ] \n", rb->layout.tp_block_nr, rb->layout.tp_frame_nr);
	info(" [ %d frames per block ]\n", rb->layout.tp_block_size / rb->layout.tp_frame_size);
	info(" [ framesize: %d bytes, blocksize: %d bytes ]\n\n", rb->layout.tp_frame_size, rb->layout.tp_block_size);
}

/**
 * mmap_virt_rx_ring - Memory maps virtual RX_RING kernel buffer into userspace 
 *                     in order to avoid syscalls for fetching packet buffers
 * @sock:             socket
 * @rb:               ring buffer
 */
void mmap_virt_rx_ring(int sock, ring_buff_t * rb)
{
	assert(rb);

	rb->buffer = mmap(0, rb->len, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
	if (rb->buffer == MAP_FAILED) {
		perr("mmap: cannot mmap the rx ring: %d - ", errno);

		destroy_virt_rx_ring(sock, rb);
		close(sock);

		exit(EXIT_FAILURE);
	}
}

/**
 * bind_dev_to_rx_ring - Binds virtual RX_RING to network device
 * @sock:               socket
 * @ifindex:            device number
 * @rb:                 ring buffer
 */
void bind_dev_to_rx_ring(int sock, int ifindex, ring_buff_t * rb)
{
	int ret;

	assert(rb);

	memset(&(rb->params), 0, sizeof(rb->params));

	rb->params.sll_family = AF_PACKET;
	rb->params.sll_protocol = htons(ETH_P_ALL);
	rb->params.sll_ifindex = ifindex;
	rb->params.sll_hatype = 0;
	rb->params.sll_halen = 0;
	rb->params.sll_pkttype = 0;

	ret = bind(sock, (struct sockaddr *)&(rb->params), sizeof(struct sockaddr_ll));
	if (ret < 0) {
		perr("bind: cannot bind device: %d - ", errno);

		close(sock);
		exit(EXIT_FAILURE);
	}
}
