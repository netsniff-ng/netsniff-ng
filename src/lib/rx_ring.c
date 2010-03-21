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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/types.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#include <netsniff-ng/pcap.h>
#include <netsniff-ng/cursor.h>
#include <netsniff-ng/dump.h>
#include <netsniff-ng/macros.h>
#include <netsniff-ng/types.h>
#include <netsniff-ng/rx_ring.h>
#include <netsniff-ng/netdev.h>
#include <netsniff-ng/config.h>
#include <netsniff-ng/signal.h>

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

	dev_speed = get_device_bitrate_generic_fallback(ifname) >> 3;
	memset(&(rb->layout), 0, sizeof(rb->layout));

	/* max: getpagesize() << 11 for i386 */
	rb->layout.tp_block_size = getpagesize() << 2;
	rb->layout.tp_frame_size = TPACKET_ALIGNMENT << 7;

	/* max: 15 for i386, old default: 1 << 13, now: approximated bandwidth size */
	rb->layout.tp_block_nr = ((dev_speed * 1100000) / rb->layout.tp_block_size) * 2;
	rb->layout.tp_frame_nr = rb->layout.tp_block_size / rb->layout.tp_frame_size * rb->layout.tp_block_nr;

 __retry_sso:
	ret = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (void *)&(rb->layout), sizeof(rb->layout));

	if (errno == ENOMEM && rb->layout.tp_block_nr > 1) {
		rb->layout.tp_block_nr >>= 1;
		rb->layout.tp_frame_nr = rb->layout.tp_block_size / rb->layout.tp_frame_size * rb->layout.tp_block_nr;

		goto __retry_sso;
	}

	if (ret < 0) {
		err("setsockopt: creation of rx_ring failed");
		close(sock);
		exit(EXIT_FAILURE);
	}

	rb->len = rb->layout.tp_block_size * rb->layout.tp_block_nr;

	info("%.2f MB allocated for receive ring \n", 1.f * rb->len / (1024 * 1024));
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
		err("mmap: cannot mmap the rx_ring");

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
		err("bind: cannot bind device");

		close(sock);
		exit(EXIT_FAILURE);
	}
}

/**
 * fetch_packets_and_print - Traverses RX_RING and prints content
 * @rb:                     ring buffer
 * @pfd:                    file descriptor for polling
 */
void fetch_packets(system_data_t * sd, int sock, ring_buff_t * rb, struct pollfd *pfd)
{
	int ret, foo, i = 0;

	pthread_t progress;

	assert(rb);
	assert(pfd);
	assert(sd);

	info("--- Listening ---\n\n");

	if (!sd->print_pkt)
		enable_print_progress_spinner();
	
	if (sd->pcap_fd != PCAP_NO_DUMP) {
		pcap_write_header(sd->pcap_fd, LINKTYPE_EN10MB, 0, PCAP_DEFAULT_SNAPSHOT_LEN);

		if (!sd->print_pkt) {
			ret = pthread_create(&progress, NULL, print_progress_spinner_dynamic, "Receive ring dumping ... |");
			if (ret) {
				err("Cannot create thread");
				exit(EXIT_FAILURE);
			}
		}
	}

	/* This is our critical path ... */
	while (likely(!sigint)) {
		while (mem_notify_user_for_rx(rb->frames[i]) && likely(!sigint)) {
			struct frame_map *fm = rb->frames[i].iov_base;
			ring_buff_bytes_t *rbb =
			    (ring_buff_bytes_t *) (rb->frames[i].iov_base + sizeof(*fm) + sizeof(short));

			/* Check if the user wants to have a specific 
			   packet type */
			if (sd->packet_type != PACKET_DONT_CARE) {
				if (fm->s_ll.sll_pkttype != sd->packet_type) {
					goto __out_notify_kernel;
				}
			}

			if (sd->pcap_fd != PCAP_NO_DUMP) {
				pcap_dump(sd->pcap_fd, &fm->tp_h, (struct ethhdr *)rbb);
				print_progress_spinner_dynamic_trigger();
			}

			if (sd->print_pkt) {
				/* This path here slows us down ... well, but
				   the user wants to see what's going on */
				sd->print_pkt(rbb, &fm->tp_h);
			}

			/* Pending singals will be delivered after netstat 
			   manipulation */
			hold_softirq(2, SIGUSR1, SIGALRM);
			/* XXX: futex */
			pthread_mutex_lock(&gs_loc_mutex);

			netstat.per_sec.frames++;
			netstat.per_sec.bytes += fm->tp_h.tp_len;

			netstat.total.frames++;
			netstat.total.bytes += fm->tp_h.tp_len;

			pthread_mutex_unlock(&gs_loc_mutex);
			restore_softirq(2, SIGUSR1, SIGALRM);

			/* Next frame */
			i = (i + 1) % rb->layout.tp_frame_nr;

 __out_notify_kernel:
			/* This is very important, otherwise kernel starts
			   to drop packages */
			mem_notify_kernel_for_rx(&(fm->tp_h));
		}

		while ((ret = poll(pfd, 1, sd->blocking_mode)) <= 0) {
			if (sigint) {
				return;
			}
		}

		if (ret > 0 && (pfd->revents & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL))) {
			if (pfd->revents & (POLLHUP | POLLRDHUP)) {
				err("Hangup on socket occured");
				return;
			} else if (pfd->revents & POLLERR) {
				/* recv is more specififc on the error */
				errno = 0;
				if (recv(sock, &foo, sizeof(foo), MSG_PEEK) != -1)
					goto __out_grab_frame;	/* Hmm... no error */
				if (errno == ENETDOWN) {
					err("Interface went down");
				} else {
					err("Receive error");
				}
				return;
			} else if (pfd->revents & POLLNVAL) {
				err("Invalid polling request on socket");
				return;
			}
		}

 __out_grab_frame:
		/* Look-ahead if current frame is status kernel, otherwise we have
		   have incoming frames and poll spins / hangs all the time :( */
		for (; ((struct tpacket_hdr *)rb->frames[i].iov_base)->tp_status
		     != TP_STATUS_USER; i = (i + 1) % rb->layout.tp_frame_nr)
			/* NOP */ ;
		/* Why this should be okay:
		   1) Current frame[i] is TP_STATUS_USER:
		   This is our original case that occurs without 
		   the for loop.
		   2) Current frame[i] is not TP_STATUS_USER:
		   poll returns correctly with return value 1 (number of 
		   file descriptors), so an event has occured which has 
		   to be POLLIN since all error conditions have been 
		   caught previously. Furthermore, during ring traversal 
		   a frame that has been set to TP_STATUS_USER will be 
		   given back to kernel on finish with TP_STATUS_KERNEL.
		   So, if we look ahead all skipped frames are not ready 
		   for user access. Since the kernel decides to put 
		   frames, which are 'behind' our pointer, into 
		   TP_STATUS_USER we do one loop and return at the 
		   correct position after passing the for loop again. If 
		   we grab frame which are 'in front of' our pointer 
		   we'll fetch them within the first for loop. 
		 */
	}
	
	if (!sd->print_pkt)
		disable_print_progress_spinner();
}
