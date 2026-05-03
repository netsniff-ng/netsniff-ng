/*
 * config.h - macOS BPF port configuration
 */
#ifndef CONFIG_H
#define CONFIG_H

/* Disable Linux-only features */
#undef  HAVE_HWTSTAMP
#undef  HAVE_TPACKET_STATS_V3

/* Platform */
#define PROGNAME        "netsniff-ng"
#define VERSION_STRING  "0.6.9-macos-bpf"

/* BPF buffer size */
#define BPF_BUFSIZE (1 << 22)

#endif /* CONFIG_H */

/* Version strings */
#ifndef VERSION_LONG
# define VERSION_LONG   "0.6.9-macos-bpf"
#endif
#ifndef GITVERSION
# define GITVERSION     "macos-bpf-port"
#endif

/* Enable tcpdump-style filter compilation via libpcap */
#define HAVE_TCPDUMP_LIKE_FILTER 1
#define NEED_TCPDUMP_LIKE_FILTER 1
