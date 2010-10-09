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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <linux/version.h>

#include "bpf.h"
#include "macros.h"
#include "types.h"
#include "replay.h"
#include "tx_ring.h"
#include "netdev.h"
#include "nsignal.h"
#include "cursor.h"
#include "xmalloc.h"

#ifdef __HAVE_TX_RING__
static void set_packet_loss_discard(int sock)
{
	int ret;
	int foo = 1;		/* we discard wrong packets */

	ret =
	    setsockopt(sock, SOL_PACKET, PACKET_LOSS, (void *)&foo,
		       sizeof(foo));
	if (ret < 0) {
		err("setsockopt: cannot set packet loss");
		close(sock);
		exit(EXIT_FAILURE);
	}
}

/**
 * destroy_virt_tx_ring - Destroys virtual TX_RING buffer
 * @sock:                socket
 * @rb:                  ring buffer
 */
void destroy_virt_tx_ring(int sock, struct ring_buff *rb)
{
	assert(rb);

	memset(&(rb->layout), 0, sizeof(rb->layout));
	setsockopt(sock, SOL_PACKET, PACKET_TX_RING, (void *)&(rb->layout),
		   sizeof(rb->layout));

	if (rb->buffer) {
		munmap(rb->buffer, rb->len);
		rb->buffer = 0;
		rb->len = 0;
	}

	xfree(rb->frames);
}

/**
 * create_virt_tx_ring - Creates virtual TX_RING buffer
 * @sock:               socket
 * @rb:                 ring buffer
 */
void create_virt_tx_ring(int sock, struct ring_buff *rb, char *ifname,
			 unsigned int usize)
{
	short nic_flags;
	int ret, dev_speed;

	assert(rb);
	assert(ifname);

	nic_flags = get_nic_flags(ifname);

	if ((nic_flags & IFF_UP) != IFF_UP) {
		warn("The interface %s is not up\n\n", ifname);
		exit(EXIT_FAILURE);
	}

	if ((nic_flags & IFF_RUNNING) != IFF_RUNNING) {
		warn("The interface %s is not running\n\n", ifname);
		exit(EXIT_FAILURE);
	}

	dev_speed = get_device_bitrate_generic_fallback(ifname);
	memset(&(rb->layout), 0, sizeof(rb->layout));

	set_packet_loss_discard(sock);

	/* max: getpagesize() << 11 for i386 */
	rb->layout.tp_block_size = getpagesize() << 2;
	rb->layout.tp_frame_size = TPACKET_ALIGNMENT << 7;

	/* max: 15 for i386, old default: 1 << 13, now: approximated bandwidth size */
	if (usize == 0) {
		rb->layout.tp_block_nr =
		    ((dev_speed * 1024 * 1024) / rb->layout.tp_block_size);
	} else {
		rb->layout.tp_block_nr =
		    usize / (rb->layout.tp_block_size / 1024);
	}

	rb->layout.tp_frame_nr =
	    rb->layout.tp_block_size / rb->layout.tp_frame_size *
	    rb->layout.tp_block_nr;

 __retry_sso:
	ret =
	    setsockopt(sock, SOL_PACKET, PACKET_TX_RING, (void *)&(rb->layout),
		       sizeof(rb->layout));

	if (errno == ENOMEM && rb->layout.tp_block_nr > 1) {
		rb->layout.tp_block_nr >>= 1;
		rb->layout.tp_frame_nr =
		    rb->layout.tp_block_size / rb->layout.tp_frame_size *
		    rb->layout.tp_block_nr;

		goto __retry_sso;
	}

	if (ret < 0) {
		err("setsockopt: creation of tx ring failed");
		close(sock);
		exit(EXIT_FAILURE);
	}

	rb->len = rb->layout.tp_block_size * rb->layout.tp_block_nr;

	info("%.2f MB allocated for transmit ring \n",
	     1.f * rb->len / (1024 * 1024));
	info(" [ %d blocks, %d frames ] \n", rb->layout.tp_block_nr,
	     rb->layout.tp_frame_nr);
	info(" [ %d frames per block ]\n",
	     rb->layout.tp_block_size / rb->layout.tp_frame_size);
	info(" [ framesize: %d bytes, blocksize: %d bytes ]\n\n",
	     rb->layout.tp_frame_size, rb->layout.tp_block_size);
}

/**
 * mmap_virt_tx_ring - Memory maps virtual TX_RING kernel buffer into userspace 
 *                     in order to avoid syscalls for transmitting packet buffers
 * @sock:             socket
 * @rb:               ring buffer
 */
void mmap_virt_tx_ring(int sock, struct ring_buff *rb)
{
	assert(rb);

	rb->buffer =
	    mmap(0, rb->len, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
	if (rb->buffer == MAP_FAILED) {
		err("mmap: cannot mmap the tx ring");

		destroy_virt_tx_ring(sock, rb);
		close(sock);

		exit(EXIT_FAILURE);
	}
}

/**
 * bind_dev_to_tx_ring - Binds virtual TX_RING to network device
 * @sock:               socket
 * @ifindex:            device number
 * @rb:                 ring buffer
 */
void bind_dev_to_tx_ring(int sock, int ifindex, struct ring_buff *rb)
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

	ret =
	    bind(sock, (struct sockaddr *)&(rb->params),
		 sizeof(struct sockaddr_ll));
	if (ret < 0) {
		err("bind: cannot bind device");
		close(sock);
		exit(EXIT_FAILURE);
	}
}

void transmit_packets(struct system_data *sd, int sock, struct ring_buff *rb)
{
	struct frame_map *fm;
	struct tpacket_hdr *header;
	uint8_t *buff;
	size_t pkt_len = 0;
	int ret;
	uint32_t i;
	struct pollfd pfd;

	assert(rb);
	assert(sd);

	pfd.fd = sock;
	pfd.revents = 0;
	pfd.events = POLLOUT;

	info("Starting transmitting\n");

	while (likely(!sigint)) {
		for (i = 0; i < rb->layout.tp_block_nr; i++) {
			fm = rb->frames[i].iov_base;
			header = (struct tpacket_hdr *)&fm->tp_h;
			buff =
			    (uint8_t *) ((uintptr_t) rb->frames[i].iov_base +
					 TPACKET_HDRLEN -
					 sizeof(struct sockaddr_ll));

			switch ((volatile uint32_t)header->tp_status) {
			case TP_STATUS_AVAILABLE:
				while ((pkt_len =
					pcap_fetch_next_packet(sd->pcap_fd,
							       header,
							       (struct ethhdr *)
							       buff)) != 0) {
					/* If the fetch packet does not match the BPF, take the next one */
					if (bpf_filter
					    (&sd->bpf, buff, header->tp_len)) {
						break;
					}
				}

				/* Prints all packets which match the BFP as unknown */
				if (pkt_len != 0 && sd->print_pkt)
					sd->print_pkt(buff, header, 5);

				/* No packets to replay or error, time to exit */
				if (pkt_len == 0)
					goto pkt_flush;

				/* Mark packet as ready to send */
				header->tp_status = TP_STATUS_SEND_REQUEST;
				break;

			case TP_STATUS_WRONG_FORMAT:
				warn("An error during transfer!\n");
				exit(EXIT_FAILURE);
				break;

			default:
				/* NOP */
				break;
			}
		}

 pkt_flush:
		ret = send(sock, NULL, 0, 0);

		if (ret < 0) {
			err("Cannot flush tx_ring with send");
		}

		/* Now we wait that the kernel place all packet on the medium */
		ret = poll(&pfd, 1, sd->blocking_mode);

		if (ret < 0)
			err("An error occured while polling on %s\n", sd->dev);

		if (pkt_len == 0)
			break;
	}
}
#else

/* 
 * XXX: do the same stuff but only with sendmsg or similar 
 */

void bind_dev_to_tx_ring(int sock, int ifindex, struct ring_buff *rb)
{
	/* NOP */
}

void mmap_virt_tx_ring(int sock, struct ring_buff *rb)
{
	/* NOP */
}

void create_virt_tx_ring(int sock, struct ring_buff *rb, char *ifname,
			 unsigned int usize)
{
	/* NOP */
}

void destroy_virt_tx_ring(int sock, struct ring_buff *rb)
{
	/* NOP */
}

int flush_virt_tx_ring(int sock, struct ring_buff *rb)
{
	return 0;
}

void transmit_packets(struct system_data *sd, int sock, struct ring_buff *rb)
{
	assert(rb);
	assert(sd);
	info("--- Transmitting ---\n\n");

	/* Dummy function */

	warn("The --replay functionality needs a kernel >= 2.6.31 \n\n");
}
#endif				/* __HAVE_TX_RING__ */
