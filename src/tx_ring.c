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

#define flushlock_lock(x) do{ (x) = 1; } while(0);
#define flushlock_unlock(x) do{ (x) = 0; } while(0);
#define flushlock_trylock(x) ((x) == 1)

struct packed_tx_data {
	struct system_data *sd;
	int sock;
	struct ring_buff *rb;
};

volatile sig_atomic_t ring_lock;
volatile sig_atomic_t send_intr = 0;

#ifdef __HAVE_TX_RING__
static void set_packet_loss_discard(int sock)
{
	int ret;
	int foo = 1;		/* we discard wrong packets */

	ret = setsockopt(sock, SOL_PACKET, PACKET_LOSS, (void *)&foo, sizeof(foo));
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
	setsockopt(sock, SOL_PACKET, PACKET_TX_RING, (void *)&(rb->layout), sizeof(rb->layout));

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
void create_virt_tx_ring(int sock, struct ring_buff *rb, char *ifname, unsigned int usize)
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
		rb->layout.tp_block_nr = ((dev_speed * 1024 * 1024) / rb->layout.tp_block_size);
	} else {
		rb->layout.tp_block_nr = usize / (rb->layout.tp_block_size / 1024);
	}

	rb->layout.tp_frame_nr = rb->layout.tp_block_size / rb->layout.tp_frame_size * rb->layout.tp_block_nr;

 __retry_sso:
	ret = setsockopt(sock, SOL_PACKET, PACKET_TX_RING, (void *)&(rb->layout), sizeof(rb->layout));

	if (errno == ENOMEM && rb->layout.tp_block_nr > 1) {
		rb->layout.tp_block_nr >>= 1;
		rb->layout.tp_frame_nr = rb->layout.tp_block_size / rb->layout.tp_frame_size * rb->layout.tp_block_nr;

		goto __retry_sso;
	}

	if (ret < 0) {
		err("setsockopt: creation of tx ring failed");
		close(sock);
		exit(EXIT_FAILURE);
	}

	rb->len = rb->layout.tp_block_size * rb->layout.tp_block_nr;

	info("%.2f MB allocated for transmit ring \n", 1.f * rb->len / (1024 * 1024));
	info(" [ %d blocks, %d frames ] \n", rb->layout.tp_block_nr, rb->layout.tp_frame_nr);
	info(" [ %d frames per block ]\n", rb->layout.tp_block_size / rb->layout.tp_frame_size);
	info(" [ framesize: %d bytes, blocksize: %d bytes ]\n\n", rb->layout.tp_frame_size, rb->layout.tp_block_size);
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

	rb->buffer = mmap(0, rb->len, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
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

	ret = bind(sock, (struct sockaddr *)&(rb->params), sizeof(struct sockaddr_ll));
	if (ret < 0) {
		err("bind: cannot bind device");
		close(sock);
		exit(EXIT_FAILURE);
	}
}

/**
 * flush_virt_tx_ring - Send payload of tx_ring in non-blocking mode
 * @sock:              socket
 * @rb:                ring buffer
 */
int flush_virt_tx_ring(int sock, struct ring_buff *rb)
{
	int rc;

	/* Flush buffers with TP_STATUS_SEND_REQUEST */
	rc = sendto(sock, NULL, 0, 0 /*MSG_DONTWAIT */ , NULL, 0);
	if (rc < 0) {
		err("Cannot flush tx_ring with sendto");
	}

	return rc;
}

/**
 * fill_virt_tx_ring_thread - Fills payload of tx_ring
 * @packed:                  packed system data
 */
static void *fill_virt_tx_ring_thread(void *packed)
{
	int loop, i;

	uint8_t *buff;
	unsigned long long packets = 0;

	struct frame_map *fm;
	struct tpacket_hdr *header;
	struct packed_tx_data *ptd;

	ptd = (struct packed_tx_data *)packed;

	for (i = 0; likely(!sigint); loop = 1) {
		do {
			int success;

			fm = ptd->rb->frames[i].iov_base;
			header = (struct tpacket_hdr *)&fm->tp_h;
			buff =
			    (uint8_t *) ((uintptr_t) ptd->rb->frames[i].iov_base + TPACKET_HDRLEN -
					 sizeof(struct sockaddr_ll));

			switch ((volatile uint32_t)header->tp_status) {
			default:
				sched_yield();
				break;

			case TP_STATUS_SEND_REQUEST:
				/* Notify kernel to pull */
				flushlock_unlock(ring_lock);
				usleep(0);
				break;

			case TP_STATUS_AVAILABLE:
				success = 0;
				while (pcap_fetch_next_packet(ptd->sd->pcap_fd, header, (struct ethhdr *)buff)) {
					printf("Fetched pkt %p\n", (void *)buff);

					/* Filter packet if user wants so */
					if (bpf_filter(&ptd->sd->bpf, buff, header->tp_len)) {
						success = 1;
						break;
					}

					versatile_print(buff, header);
				}
				printf("Success? %u\n", success);
				if (success == 0)
					goto out;
				loop = 0;
				versatile_print(buff, header);
				break;

			case TP_STATUS_WRONG_FORMAT:
				warn("An error during transfer!\n");
				exit(EXIT_FAILURE);
				break;
			}
		} while (loop == 1 && likely(!sigint));

		/* We're done! */
		mem_notify_kernel_for_tx(header);
		packets++;
		/* Next frame */
		i = (i + 1) % ptd->rb->layout.tp_frame_nr;
	}

	/* Pull the rest */
	flushlock_unlock(ring_lock);
	/* XXX: Thread may exit */
	send_intr = 1;

 out:
	info("Transmit ring has pushed %llu packets!\n", packets);
	pthread_exit(0);
}

/**
 * flush_virt_tx_ring_thread - Sends payload of tx_ring
 * @packed:                   packed system data
 */
static void *flush_virt_tx_ring_thread(void *packed)
{
	int i, ret, errors = 0;

	struct frame_map *fm;
	struct tpacket_hdr *header;
	struct packed_tx_data *ptd;
	struct spinner_thread_context spinner_ctx = { 0 };

	spinner_set_msg(&spinner_ctx, DEFAULT_TX_RING_SILENT_MESSAGE);

	ptd = (struct packed_tx_data *)packed;

	for (; likely(!send_intr); errors = 0) {
		ret = spinner_create(&spinner_ctx);
		if (ret) {
			err("Cannot create spinner thread");
			exit(EXIT_FAILURE);
		}

		ret = flush_virt_tx_ring(ptd->sock, ptd->rb);
		if (ret < 0) {
			exit(EXIT_FAILURE);
		}

		spinner_trigger_event(&spinner_ctx);

		for (i = 0; i < ptd->rb->layout.tp_frame_nr; i++) {
			fm = ptd->rb->frames[i].iov_base;
			header = (struct tpacket_hdr *)&fm->tp_h;

			switch ((volatile uint32_t)header->tp_status) {
			case TP_STATUS_SEND_REQUEST:
				warn("Frame has not been sent %p!\n", (void *)header);
				fflush(stdout);
				errors++;
				break;

			case TP_STATUS_LOSING:
				warn("Transfer error of frame!\n");
				fflush(stdout);
				errors++;
				break;

			default:
				break;
			}
		}

		if (errors > 0) {
			warn("%d errors occured during tx_ring flush!\n", errors);
		} else {
			info("Transmit ring has been flushed.\n\n");
		}
	}

	spinner_cancel(&spinner_ctx);
	pthread_exit(0);
}

/**
 * transmit_packets - TX_RING critical path
 * @sd:              config data
 * @sock:            socket
 * @rb:              ring buffer
 */
void transmit_packets(struct system_data *sd, int sock, struct ring_buff *rb)
{
	assert(rb);
	assert(sd);

	int ret;

	pthread_t send, fill;
	pthread_attr_t attr_send, attr_fill;

	struct sched_param para_send, para_fill;
	struct packed_tx_data ptd = {
		.sd = sd,
		.sock = sock,
		.rb = rb,
	};

	info("--- Transmitting ---\n");
	info("!!! Experimental !!!\n\n");

	//flushlock_lock(ring_lock);

	pthread_attr_init(&attr_send);
	pthread_attr_init(&attr_fill);

	pthread_attr_setschedpolicy(&attr_send, SCHED_RR);
	pthread_attr_setschedpolicy(&attr_fill, SCHED_RR);

	para_send.sched_priority = 20;
	pthread_attr_setschedparam(&attr_send, &para_send);

	para_fill.sched_priority = 20;
	pthread_attr_setschedparam(&attr_fill, &para_fill);

	ret = pthread_create(&fill, &attr_fill, fill_virt_tx_ring_thread, &ptd);
	if (ret) {
		err("Cannot create fill thread");
		exit(EXIT_FAILURE);
	}

	ret = pthread_create(&send, &attr_send, flush_virt_tx_ring_thread, &ptd);
	if (ret) {
		err("Cannot create send thread");
		exit(EXIT_FAILURE);
	}

	pthread_join(fill, NULL);
	pthread_join(send, NULL);
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

void create_virt_tx_ring(int sock, struct ring_buff *rb, char *ifname, unsigned int usize)
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
#if 0
	struct packed_tx_data ptd = {
		.sd = sd,
		.sock = sock,
		.rb = rb,
	};
#endif
	info("--- Transmitting ---\n\n");

	/* Dummy function */

	warn("Not yet implemented!\n\n");
}
#endif				/* __HAVE_TX_RING__ */
