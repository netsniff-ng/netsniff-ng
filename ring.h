/*
 * ring.h - macOS BPF replacement for Linux AF_PACKET ring
 * Stubs tpacket types so upper layers compile unchanged
 */

#ifndef RING_H
#define RING_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "linux_compat.h"
#include "built_in.h"
#include "die.h"
#include "dev.h"
#include "config.h"

/* ------------------------------------------------------------------ */
/* Stub Linux tpacket types — referenced throughout the codebase       */
/* ------------------------------------------------------------------ */

#ifndef TP_STATUS_USER
# define TP_STATUS_USER         (1 << 0)
#endif
#ifndef TP_STATUS_KERNEL
# define TP_STATUS_KERNEL       0
#endif
#ifndef TP_STATUS_SEND_REQUEST
# define TP_STATUS_SEND_REQUEST (1 << 0)
#endif
#ifndef TP_STATUS_SENDING
# define TP_STATUS_SENDING      (1 << 1)
#endif
#ifndef TP_STATUS_VLAN_VALID
# define TP_STATUS_VLAN_VALID   (1 << 4)
#endif
#ifndef TP_STATUS_VLAN_TPID_VALID
# define TP_STATUS_VLAN_TPID_VALID (1 << 6)
#endif

#ifndef POLLRDNORM
# define POLLRDNORM 0x0040
#endif

/* tpacket2_hdr defined in linux_compat.h */

/* Minimal tpacket_req stub */
struct tpacket_req {
    unsigned int tp_block_size;
    unsigned int tp_block_nr;
    unsigned int tp_frame_size;
    unsigned int tp_frame_nr;
};

/* sockaddr_ll defined in linux_compat.h */

/* tpacket_uhdr union — stub using our tpacket2_hdr */
union tpacket_uhdr {
    struct tpacket2_hdr *h2;
    void *raw;
};

#define tpacket_uhdr(hdr, member, v3) (((hdr).h2)->member)

static inline uint16_t tpacket_uhdr_vlan_tci(union tpacket_uhdr *hdr,
                                              bool v3 __attribute__((unused)))
{
    return hdr->h2->tp_vlan_tci;
}

static inline uint16_t tpacket_uhdr_vlan_proto(union tpacket_uhdr *hdr,
                                                bool v3 __attribute__((unused)))
{
    return hdr->h2->tp_vlan_tpid;
}

static inline bool tpacket_has_vlan_info(union tpacket_uhdr *hdr)
{
    return hdr->h2->tp_status &
           (TP_STATUS_VLAN_VALID | TP_STATUS_VLAN_TPID_VALID);
}

/* frame_map — used by rx/tx walk loops */
struct frame_map {
    struct tpacket2_hdr tp_h;
    struct sockaddr_ll  s_ll;
};

/* ------------------------------------------------------------------ */
/* ring struct — mm_space is our BPF read buffer                       */
/* ------------------------------------------------------------------ */

struct ring {
    struct iovec       *frames;
    uint8_t            *mm_space;
    size_t              mm_len;
    struct sockaddr_ll  s_ll;
    union {
        struct tpacket_req layout;
        uint8_t            raw;
    };
};

/* ------------------------------------------------------------------ */
/* SOL_PACKET / PACKET_VERSION stubs — referenced in set_sockopt calls */
/* ------------------------------------------------------------------ */

#ifndef SOL_PACKET
# define SOL_PACKET          263
#endif
#ifndef PACKET_VERSION
# define PACKET_VERSION      10
#endif
#ifndef TPACKET_V2
# define TPACKET_V2          1
#endif

static inline void __set_sockopt_tpacket(int sock __attribute__((unused)),
                                         int val  __attribute__((unused))) {}
static inline void set_sockopt_tpacket_v2(int sock __attribute__((unused))) {}
static inline void set_sockopt_tpacket_v3(int sock __attribute__((unused))) {}
static inline int  get_sockopt_tpacket(int sock __attribute__((unused)))
{ return TPACKET_V2; }

/* ------------------------------------------------------------------ */
/* Inline helpers                                                       */
/* ------------------------------------------------------------------ */

static inline void next_rnd_slot(unsigned int *it, struct ring *ring)
{
    *it = rand() % ring->layout.tp_frame_nr;
}

static inline size_t ring_size(const char *ifname, size_t size)
{
    if (size > 0) return size;
    size = device_bitrate(ifname);
    size = (size * 1000000) / 8 * 2;
    if (size == 0) size = 1 << 26;
    return size;
}

static inline unsigned int ring_frame_size(struct ring *ring)
{
    return ring->layout.tp_frame_size;
}

static inline void ring_verify_layout(struct ring *ring __attribute__((unused))) {}

static inline void shrink_ring_layout_generic(struct ring *ring)
{
    ring->layout.tp_block_nr >>= 1;
    ring->layout.tp_frame_nr  = ring->layout.tp_block_size
                               / ring->layout.tp_frame_size
                               * ring->layout.tp_block_nr;
}

static inline void tpacket_hdr_clone(struct tpacket2_hdr *dst,
                                     struct tpacket2_hdr *src)
{
    dst->tp_sec     = src->tp_sec;
    dst->tp_nsec    = src->tp_nsec;
    dst->tp_snaplen = src->tp_snaplen;
    dst->tp_len     = src->tp_len;
}

static inline void prepare_polling(int sock, struct pollfd *pfd)
{
    memset(pfd, 0, sizeof(*pfd));
    pfd->fd      = sock;
    pfd->revents = 0;
    pfd->events  = POLLIN | POLLRDNORM | POLLERR;
}

/* ------------------------------------------------------------------ */
/* Extern declarations                                                  */
/* ------------------------------------------------------------------ */

extern int  af_socket(int type);
extern int  pf_socket(void);
extern void bind_ring_generic(int sock, struct ring *ring, int ifindex,
                              bool tx_only);
extern void setup_rx_ring(int sock, struct ring *ring);
extern void setup_tx_ring(int sock, struct ring *ring);
extern void mmap_ring(int sock, struct ring *ring);
extern void alloc_ring_frames(struct ring *ring, int num, size_t size);
extern void unmap_ring(int sock, struct ring *ring);
extern void setup_ring_layout_generic(struct ring *ring, size_t size,
                                      bool jumbo_support);
extern void mmap_ring_generic(int sock, struct ring *ring);
extern void alloc_ring_frames_generic(struct ring *ring, size_t num,
                                      size_t size);

#endif /* RING_H */
