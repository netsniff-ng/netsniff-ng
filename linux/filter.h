/*
 * linux/filter.h - macOS stub for BPF filter structures
 * Avoids struct bpf_insn collision when libpcap headers are in use
 */
#ifndef LINUX_FILTER_H
#define LINUX_FILTER_H

#include <stdint.h>

/* Skip net/bpf.h if libpcap's bpf.h has already defined struct bpf_insn */
#ifndef lib_pcap_bpf_h
# include <net/bpf.h>
#endif

struct sock_filter {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
};

struct sock_fprog {
    uint16_t            len;
    struct sock_filter *filter;
};

#ifndef BPF_STMT
# define BPF_STMT(code, k) { (uint16_t)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
# define BPF_JUMP(code, k, jt, jf) { (uint16_t)(code), jt, jf, k }
#endif

#endif /* LINUX_FILTER_H */
