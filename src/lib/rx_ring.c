/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4  \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l80 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com>
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

/**
 * destroy_virt_ring - Destroys virtual RX_RING buffer
 * @sock:             socket
 * @rb:               ring buffer
 */
void destroy_virt_ring(int sock, ring_buff_t * rb)
{
	assert(rb);

	memset(&(rb->layout), 0, sizeof(rb->layout));
	setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (void *)&(rb->layout),
		   sizeof(rb->layout));

	if (rb->buffer) {
		munmap(rb, rb->len);
		rb->buffer = 0;
		rb->len = 0;
	}

	free(rb->frames);
}

/**
 * create_virt_ring - Creates virtual RX_RING buffer
 * @sock:            socket
 * @rb:              ring buffer
 */
void create_virt_ring(int sock, ring_buff_t * rb)
{
	int ret;

	assert(rb);

	memset(&(rb->layout), 0, sizeof(rb->layout));

	/* max: getpagesize() << 11 for i386 */
	rb->layout.tp_block_size = getpagesize() << 2;
	rb->layout.tp_frame_size = TPACKET_ALIGNMENT << 7;

	/* max: 15 for i386 */
	rb->layout.tp_block_nr = 1 << 13;
	rb->layout.tp_frame_nr =
	    rb->layout.tp_block_size / rb->layout.tp_frame_size *
	    rb->layout.tp_block_nr;

 __retry_sso:
	ret = setsockopt(sock, SOL_PACKET, PACKET_RX_RING,
			 (void *)&(rb->layout), sizeof(rb->layout));

	if (errno == ENOMEM && rb->layout.tp_block_nr > 1) {
		rb->layout.tp_block_nr >>= 1;
		rb->layout.tp_frame_nr =
		    rb->layout.tp_block_size / rb->layout.tp_frame_size *
		    rb->layout.tp_block_nr;

		goto __retry_sso;
	}

	if (ret < 0) {
		perr("setsockopt: creation of rx ring failed: %d - ", errno);

		close(sock);
		exit(EXIT_FAILURE);
	}

	rb->len = rb->layout.tp_block_size * rb->layout.tp_block_nr;

	dbg("%.2f MB allocated for rx ring: %d blocks, %d frames, "
	    "%d frames per block, framesize: %d bytes, blocksize: %d bytes \n",
	    1. * rb->len / (1024 * 1024),
	    rb->layout.tp_block_nr,
	    rb->layout.tp_frame_nr,
	    rb->layout.tp_block_size / rb->layout.tp_frame_size,
	    rb->layout.tp_frame_size, rb->layout.tp_block_size);
}

/**
 * mmap_virt_ring - Memory maps virtual RX_RING kernel buffer into userspace 
 *                  in order to avoid syscalls for fetching packet buffers
 * @sock:          socket
 * @rb:            ring buffer
 */
void mmap_virt_ring(int sock, ring_buff_t * rb)
{
	assert(rb);

	rb->buffer = mmap(0, rb->len, PROT_READ | PROT_WRITE, MAP_SHARED,
			  sock, 0);
	if (rb->buffer == MAP_FAILED) {
		perr("mmap: cannot mmap the rx ring: %d - ", errno);

		destroy_virt_ring(sock, rb);
		close(sock);

		exit(EXIT_FAILURE);
	}
}

/**
 * bind_dev_to_ring - Binds virtual RX_RING to network device
 * @sock:            socket
 * @ifindex:         device number
 * @rb:              ring buffer
 */
void bind_dev_to_ring(int sock, int ifindex, ring_buff_t * rb)
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

	ret = bind(sock, (struct sockaddr *)&(rb->params),
		   sizeof(struct sockaddr_ll));
	if (ret < 0) {
		perr("bind: cannot bind device: %d - ", errno);

		close(sock);
		exit(EXIT_FAILURE);
	}
}

/**
 * put_dev_into_promisc_mode - Puts network device into promiscuous mode
 * @sock:                     socket
 * @ifindex:                  device number
 */
void put_dev_into_promisc_mode(int sock, int ifindex)
{
	int ret;
	struct packet_mreq mr;

	memset(&mr, 0, sizeof(mr));

	mr.mr_ifindex = ifindex;
	mr.mr_type = PACKET_MR_PROMISC;

	/* This is better than ioctl(), because the kernel now manages the 
	   promisc flag for itself via internal counters. If the socket will 
	   be closed the kernel decrements the counters automatically which 
	   will not work with ioctl(). There, you have to manage things 
	   manually ... */

	ret = setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
			 &mr, sizeof(mr));
	if (ret < 0) {
		perr("setsockopt: cannot set dev %d to promisc mode: %d - ",
		     ifindex, errno);

		close(sock);
		exit(EXIT_FAILURE);
	}
}

/**
 * inject_kernel_bpf - Binds filter code to socket
 * @sock:             socket
 * @bpf:              Berkeley Packet Filter code
 * @len:              length of bpf
 */
void inject_kernel_bpf(int sock, struct sock_filter *bpf, int len)
{
	int ret;
	struct sock_fprog filter;

	assert(bpf);

	memset(&filter, 0, sizeof(filter));

	filter.len = len / sizeof(struct sock_filter);
	filter.filter = bpf;

	ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
			 &filter, sizeof(filter));
	if (ret < 0) {
		perr("setsockopt: filter cannot be injected: %d - ", errno);

		close(sock);
		exit(EXIT_FAILURE);
	}
}

/**
 * ethdev_to_ifindex - Translates device name into device number
 * @sock:             socket
 * @dev:              device name
 */
int ethdev_to_ifindex(int sock, char *dev)
{
	int ret;
	struct ifreq ethreq;

	memset(&ethreq, 0, sizeof(ethreq));
	strncpy(ethreq.ifr_name, dev, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFINDEX, &ethreq);
	if (ret < 0) {
		perr("ioctl: cannot determine dev number for %s: %d - ",
		     ethreq.ifr_name, errno);

		close(sock);
		exit(EXIT_FAILURE);
	}

	return (ethreq.ifr_ifindex);
}

/**
 * net_stat - Grabs and prints current socket statistics
 * @sock:    socket
 */
void net_stat(int sock)
{
	int ret;
	struct tpacket_stats kstats;
	socklen_t slen = sizeof(kstats);

	memset(&kstats, 0, sizeof(kstats));

	ret = getsockopt(sock, SOL_PACKET, PACKET_STATISTICS, &kstats, &slen);
	if (ret > -1) {
		dbg("%d frames incoming\n", kstats.tp_packets);
		dbg("%d frames passed filter\n",
		    kstats.tp_packets - kstats.tp_drops);
		dbg("%d frames failed filter (due to out of space)\n",
		    kstats.tp_drops);
	}
}

/**
 * alloc_pf_sock - Allocates a raw PF_PACKET socket
 */
int alloc_pf_sock(void)
{
	int sock = socket(PF_PACKET, SOCK_RAW, 0);
	if (sock < 0) {
		perr("alloc pf socket");
		exit(EXIT_FAILURE);
	}

	return (sock);
}

/**
 * parse_rules - Parses a BPF rulefile
 * @rulefile:   path to rulefile
 * @bpf:        sock filter
 * @len:        len of bpf
 */
void parse_rules(char *rulefile, struct sock_filter **bpf, int *len)
{
	int ret;
	uint32_t count;
	char buff[128] = { 0 };

	struct sock_filter sf_single;

	assert(bpf);

	FILE *fp = fopen(rulefile, "r");
	if (!fp) {
		perr("cannot read rulefile - ");
		exit(EXIT_FAILURE);
	}

	dbg("parsing rulefile %s\n", rulefile);

	count = 0;
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		memset(&sf_single, 0, sizeof(sf_single));

		ret = sscanf(buff, "{ 0x%x, %d, %d, 0x%08x },",
			     (unsigned int *)((void *)&(sf_single.code)),
			     (int *)((void *)&(sf_single.jt)),
			     (int *)((void *)&(sf_single.jf)), &(sf_single.k));
		if (ret != 4) {
			/* No valid bpf opcode format, might be a comment or 
			   a syntax error */
			continue;
		}

		*len += 1;
		*bpf = (struct sock_filter *)realloc(*bpf,
						     *len * sizeof(sf_single));

		memcpy(&(*bpf)[*len - 1], &sf_single, sizeof(sf_single));

		dbg("line %d: { 0x%x, %d, %d, 0x%08x }\n", count++,
		    (*bpf)[*len - 1].code,
		    (*bpf)[*len - 1].jt,
		    (*bpf)[*len - 1].jf, (*bpf)[*len - 1].k);
	}

	fclose(fp);
}
