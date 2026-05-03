/*
 * ring.c - macOS BPF replacement for AF_PACKET ring buffer
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <net/bpf.h>
#include <sys/ioctl.h>

#include "ring.h"
#include "die.h"

#define BPF_DEV_MAX  256
#define BPF_BUFSIZE  (1 << 22)  /* 4MB */

void bind_ring_generic(int sock, struct ring *ring, int ifindex, bool tx_only)
{
    struct ifreq ifr;
    u_int bufsize = BPF_BUFSIZE;
    u_int enable  = 1;

    /* Resolve ifindex → name */
    memset(&ifr, 0, sizeof(ifr));
    if (if_indextoname(ifindex, ifr.ifr_name) == NULL)
        panic("if_indextoname(%d) failed: %s\n", ifindex, strerror(errno));

    if (ioctl(sock, BIOCSBLEN, &bufsize) < 0)
        panic("BIOCSBLEN: %s\n", strerror(errno));

    if (ioctl(sock, BIOCSETIF, &ifr) < 0)
        panic("BIOCSETIF(%s): %s\n", ifr.ifr_name, strerror(errno));

    ioctl(sock, BIOCIMMEDIATE, &enable);

    if (!tx_only)
        ioctl(sock, BIOCPROMISC, NULL);

    if (ioctl(sock, BIOCGBLEN, &bufsize) < 0)
        panic("BIOCGBLEN: %s\n", strerror(errno));

    ring->layout.tp_frame_size = bufsize;
    ring->mm_len   = bufsize;
    ring->mm_space = malloc(bufsize);
    if (!ring->mm_space)
        panic("Cannot allocate BPF ring buffer\n");
}

void setup_rx_ring(int sock, struct ring *ring)   { (void)sock; (void)ring; }
void setup_tx_ring(int sock, struct ring *ring)   { (void)sock; (void)ring; }
void mmap_ring(int sock, struct ring *ring)       { (void)sock; (void)ring; }
void alloc_ring_frames(struct ring *ring, int n, size_t s) {
    (void)ring; (void)n; (void)s;
}

void setup_ring_layout_generic(struct ring *ring, size_t size,
                                bool jumbo_support)
{
    (void)jumbo_support;
    ring->layout.tp_frame_size = size ? size : BPF_BUFSIZE;
    ring->layout.tp_frame_nr   = 1;
    ring->layout.tp_block_size = ring->layout.tp_frame_size;
    ring->layout.tp_block_nr   = 1;
}

void mmap_ring_generic(int sock, struct ring *ring) { (void)sock; (void)ring; }
void alloc_ring_frames_generic(struct ring *ring, size_t n, size_t s) {
    (void)ring; (void)n; (void)s;
}

void unmap_ring(int sock, struct ring *ring)
{
    free(ring->mm_space);
    ring->mm_space = NULL;
    (void)sock;
}

void ring_rx_setup(struct ring *ring, int sock, size_t size, int ifindex,
                    struct pollfd *poll, bool v3, bool jumbo_support,
                    bool verbose, uint32_t fanout_group, uint32_t fanout_type)
{
    bind_ring_generic(sock, ring, ifindex, false);
    if (poll) {
        poll->fd = sock;
        poll->events = POLLIN;
    }
    (void)size; (void)v3; (void)jumbo_support; (void)verbose;
    (void)fanout_group; (void)fanout_type;
}

void ring_tx_setup(struct ring *ring, int sock, size_t size, int ifindex,
                    bool jumbo_support, bool verbose)
{
    bind_ring_generic(sock, ring, ifindex, true);
    (void)size; (void)jumbo_support; (void)verbose;
}

void destroy_rx_ring(int sock, struct ring *ring)
{
    unmap_ring(sock, ring);
}

void destroy_tx_ring(int sock, struct ring *ring)
{
    unmap_ring(sock, ring);
}

int get_rx_net_stats(int sock, uint64_t *packets, uint64_t *drops, bool v3)
{
    struct bpf_stat bs;
    if (ioctl(sock, BIOCGSTATS, &bs) < 0) return -1;
    if (packets) *packets = bs.bs_recv;
    if (drops)   *drops   = bs.bs_drop;
    (void)v3;
    return 0;
}
