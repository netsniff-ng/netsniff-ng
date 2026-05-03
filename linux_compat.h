#include <sys/sockio.h>
/*
 * linux_compat.h - macOS shims for Linux net constants
 */
#ifndef LINUX_COMPAT_H
#define LINUX_COMPAT_H

#include <stdint.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* ifindex — macOS uses if_nametoindex() but also has SIOCGIFINDEX */
#ifndef SIOCGIFINDEX
# define SIOCGIFINDEX SIOCGIFADDR
#endif

/* ifr_ifindex shim */
#ifndef ifr_ifindex
# define ifr_ifindex ifr_ifru.ifru_flags  /* placeholder, patched in dev.c */
#endif

/* Hardware address */
#ifndef SIOCGIFHWADDR
# define SIOCGIFHWADDR SIOCGIFLLADDR
#endif

#ifndef ifr_hwaddr
# define ifr_hwaddr ifr_addr
#endif

#ifndef IFHWADDRLEN
# define IFHWADDRLEN 6
#endif

/* ARPHRD types — from linux/if_arp.h */
#ifndef ARPHRD_ETHER
# define ARPHRD_ETHER       1
#endif
#ifndef ARPHRD_EETHER
# define ARPHRD_EETHER      2
#endif
#ifndef ARPHRD_AX25
# define ARPHRD_AX25        3
#endif
#ifndef ARPHRD_PRONET
# define ARPHRD_PRONET      4
#endif
#ifndef ARPHRD_CHAOS
# define ARPHRD_CHAOS       5
#endif
#ifndef ARPHRD_IEEE802
# define ARPHRD_IEEE802     6
#endif
#ifndef ARPHRD_ARCNET
# define ARPHRD_ARCNET      7
#endif
#ifndef ARPHRD_APPLETLK
# define ARPHRD_APPLETLK    8
#endif
#ifndef ARPHRD_DLCI
# define ARPHRD_DLCI        15
#endif
#ifndef ARPHRD_ATM
# define ARPHRD_ATM         19
#endif
#ifndef ARPHRD_METRICOM
# define ARPHRD_METRICOM    23
#endif
#ifndef ARPHRD_IEEE1394
# define ARPHRD_IEEE1394    24
#endif
#ifndef ARPHRD_INFINIBAND
# define ARPHRD_INFINIBAND  32
#endif
#ifndef ARPHRD_SLIP
# define ARPHRD_SLIP        256
#endif
#ifndef ARPHRD_CSLIP
# define ARPHRD_CSLIP       257
#endif
#ifndef ARPHRD_SLIP6
# define ARPHRD_SLIP6       258
#endif
#ifndef ARPHRD_CSLIP6
# define ARPHRD_CSLIP6      259
#endif
#ifndef ARPHRD_RSRVD
# define ARPHRD_RSRVD       260
#endif
#ifndef ARPHRD_ADAPT
# define ARPHRD_ADAPT       264
#endif
#ifndef ARPHRD_ROSE
# define ARPHRD_ROSE        270
#endif
#ifndef ARPHRD_X25
# define ARPHRD_X25         271
#endif
#ifndef ARPHRD_PPP
# define ARPHRD_PPP         512
#endif
#ifndef ARPHRD_LOOPBACK
# define ARPHRD_LOOPBACK    772
#endif
#ifndef ARPHRD_VOID
# define ARPHRD_VOID        0xFFFF
#endif

/* ethtool_drvinfo stub */
#ifndef ETHTOOL_GDRVINFO
# define ETHTOOL_GDRVINFO 0x00000003
#endif

struct ethtool_drvinfo {
    uint32_t cmd;
    char     driver[32];
    char     version[32];
    char     fw_version[32];
    char     bus_info[32];
    char     reserved1[32];
    char     reserved2[16];
    uint32_t n_priv_flags;
    uint32_t n_stats;
    uint32_t testinfo_len;
    uint32_t eedump_len;
    uint32_t regdump_len;
};

/* iw_quality and iw_statistics defined in wireless_stub.h */


#ifndef ARPHRD_HWX25
# define ARPHRD_HWX25    272
#endif
#ifndef ARPHRD_HDLC
# define ARPHRD_HDLC     513
#endif
#ifndef ARPHRD_LAPB
# define ARPHRD_LAPB     516
#endif
#ifndef ARPHRD_DDCMP
# define ARPHRD_DDCMP    517
#endif
#ifndef ARPHRD_RAWHDLC
# define ARPHRD_RAWHDLC  518
#endif
#ifndef ARPHRD_TUNNEL
# define ARPHRD_TUNNEL   768
#endif
#ifndef ARPHRD_TUNNEL6
# define ARPHRD_TUNNEL6  769
#endif
#ifndef ARPHRD_FRAD
# define ARPHRD_FRAD     770
#endif
#ifndef ARPHRD_SKIP
# define ARPHRD_SKIP     771
#endif
#ifndef ARPHRD_LOCALTLK
# define ARPHRD_LOCALTLK 773
#endif
#ifndef ARPHRD_FDDI
# define ARPHRD_FDDI     774
#endif
#ifndef ARPHRD_BIF
# define ARPHRD_BIF      775
#endif
#ifndef ARPHRD_SIT
# define ARPHRD_SIT      776
#endif
#ifndef ARPHRD_IPDDP
# define ARPHRD_IPDDP    777
#endif
#ifndef ARPHRD_IPGRE
# define ARPHRD_IPGRE    778
#endif
#ifndef ARPHRD_PIMREG
# define ARPHRD_PIMREG   779
#endif
#ifndef ARPHRD_HIPPI
# define ARPHRD_HIPPI    780
#endif
#ifndef ARPHRD_ASH
# define ARPHRD_ASH      781
#endif
#ifndef ARPHRD_ECONET
# define ARPHRD_ECONET   782
#endif
#ifndef ARPHRD_IRDA
# define ARPHRD_IRDA     783
#endif
#ifndef ARPHRD_NONE
# define ARPHRD_NONE     0xFFFE
#endif

#ifndef ARPHRD_CISCO
# define ARPHRD_CISCO   513
#endif


/* sys/sockio.h has SIOCGIFLLADDR on macOS */
#include <sys/sockio.h>

/* Fibre Channel ARPHRD types */
#ifndef ARPHRD_FCPP
# define ARPHRD_FCPP        784
#endif
#ifndef ARPHRD_FCAL
# define ARPHRD_FCAL        785
#endif
#ifndef ARPHRD_FCPL
# define ARPHRD_FCPL        786
#endif
#ifndef ARPHRD_FCFABRIC
# define ARPHRD_FCFABRIC    787
#endif
#ifndef ARPHRD_IEEE802_TR
# define ARPHRD_IEEE802_TR  800
#endif
#ifndef ARPHRD_IEEE80211
# define ARPHRD_IEEE80211   801
#endif
#ifndef ARPHRD_IEEE80211_PRISM
# define ARPHRD_IEEE80211_PRISM 802
#endif
#ifndef ARPHRD_IEEE80211_RADIOTAP
# define ARPHRD_IEEE80211_RADIOTAP 803
#endif
#ifndef ARPHRD_IEEE802154
# define ARPHRD_IEEE802154  804
#endif



/* tpacket2_hdr - must be visible to pcap_io.h */
#ifndef TPACKET2_HDR_DEFINED
#define TPACKET2_HDR_DEFINED
struct tpacket2_hdr {
    uint32_t tp_status;
    uint32_t tp_len;
    uint32_t tp_snaplen;
    uint16_t tp_mac;
    uint16_t tp_net;
    uint32_t tp_sec;
    uint32_t tp_nsec;
    uint16_t tp_vlan_tci;
    uint16_t tp_vlan_tpid;
    uint8_t  tp_padding[4];
};
#endif


/* tpacket2_hdr - must be visible to pcap_io.h */
#ifndef TPACKET2_HDR_DEFINED
#define TPACKET2_HDR_DEFINED
struct tpacket2_hdr {
    uint32_t tp_status;
    uint32_t tp_len;
    uint32_t tp_snaplen;
    uint16_t tp_mac;
    uint16_t tp_net;
    uint32_t tp_sec;
    uint32_t tp_nsec;
    uint16_t tp_vlan_tci;
    uint16_t tp_vlan_tpid;
    uint8_t  tp_padding[4];
};
#endif

/* sockaddr_ll - must be defined before pcap_io.h uses it */
#ifndef SOCKADDR_LL_DEFINED
#define SOCKADDR_LL_DEFINED
struct sockaddr_ll {
    uint16_t sll_family;
    uint16_t sll_protocol;
    int      sll_ifindex;
    uint16_t sll_hatype;
    uint8_t  sll_pkttype;
    uint8_t  sll_halen;
    uint8_t  sll_addr[8];
};
#endif

/* Linux kernel integer types */
#ifndef __u8
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t   __s8;
typedef int16_t  __s16;
typedef int32_t  __s32;
typedef int64_t  __s64;
#endif

/* Packet types */
#ifndef PACKET_HOST
# define PACKET_HOST        0
# define PACKET_BROADCAST   1
# define PACKET_MULTICAST   2
# define PACKET_OTHERHOST   3
# define PACKET_OUTGOING    4
# define PACKET_LOOPBACK    5
#endif

/* Minimal nlmsghdr stub for dissector.h */
#ifndef NLMSG_ALIGNTO
# define NLMSG_ALIGNTO 4
struct nlmsghdr {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
};
#endif

/* Linux-only open flags — no-ops on macOS */
#ifndef O_LARGEFILE
# define O_LARGEFILE 0
#endif
#ifndef O_NOATIME
# define O_NOATIME 0
#endif

/* tpacket2 header length */
#ifndef TPACKET2_HDRLEN
# define TPACKET2_HDRLEN (sizeof(struct tpacket2_hdr) + sizeof(struct sockaddr_ll))
#endif

/* BPF socket filter attach/detach — macOS uses /dev/bpf directly */
#ifndef SO_ATTACH_FILTER
# define SO_ATTACH_FILTER 26
#endif
#ifndef SO_DETACH_FILTER
# define SO_DETACH_FILTER 27
#endif

/* CPU affinity stubs — macOS uses thread_policy_set */
#ifndef cpu_set_t
typedef unsigned long cpu_set_t;
# define CPU_ZERO(s)    (*(s) = 0)
# define CPU_SET(c,s)   (*(s) |= (1UL << (c)))
# define CPU_ISSET(c,s) (*(s) & (1UL << (c)))
#endif
#ifndef sched_setaffinity
# define sched_setaffinity(pid,sz,set) (0)
#endif
#ifndef sched_setscheduler
# define sched_setscheduler(pid,pol,par) (0)
#endif
#ifndef sched_setparam
# define sched_setparam(pid,par) (0)
#endif

/* ioprio — Linux-only, no-op on macOS */
#ifndef SYS_ioprio_set
# define SYS_ioprio_set 0
# define SYS_ioprio_get 0
#endif

/* ETCDIRE_STRING — config file path */
#ifndef ETCDIRE_STRING
# define ETCDIRE_STRING "/etc/netsniff-ng"
#endif

#include <pthread.h>
/* rwlock — map to pthread_rwlock */
struct rwlock {
    pthread_rwlock_t lock;
};
static inline void rwlock_init(struct rwlock *l)    { pthread_rwlock_init(&l->lock, NULL); }
static inline void rwlock_destroy(struct rwlock *l) { pthread_rwlock_destroy(&l->lock); }
static inline void rwlock_rd_lock(struct rwlock *l) { pthread_rwlock_rdlock(&l->lock); }
static inline void rwlock_wr_lock(struct rwlock *l) { pthread_rwlock_wrlock(&l->lock); }
static inline void rwlock_unlock(struct rwlock *l)  { pthread_rwlock_unlock(&l->lock); }

/* PF_PACKET / SOL_PACKET — not on macOS, BPF handles this */
#ifndef PF_PACKET
# define PF_PACKET      17
#endif
#ifndef SOL_PACKET
# define SOL_PACKET     263
#endif
#ifndef PACKET_QDISC_BYPASS
# define PACKET_QDISC_BYPASS 20
#endif
#ifndef SO_PRIORITY
# define SO_PRIORITY    12
#endif
#ifndef SOL_IP
# define SOL_IP         IPPROTO_IP
#endif
#ifndef IP_MTU_DISCOVER
# define IP_MTU_DISCOVER 10
#endif
#ifndef IP_PMTUDISC_DONT
# define IP_PMTUDISC_DONT 0
#endif

/* BSD tcphdr field name shims */
#include <netinet/tcp.h>
#ifndef TH_FIN
# define TH_FIN  0x01
#endif
/* Map Linux tcphdr bitfield names to BSD accessor macros */
#define tcp_fin(t)  ((t)->th_flags & TH_FIN)
#define tcp_syn(t)  ((t)->th_flags & TH_SYN)
#define tcp_rst(t)  ((t)->th_flags & TH_RST)
#define tcp_psh(t)  ((t)->th_flags & TH_PUSH)
#define tcp_ack(t)  ((t)->th_flags & TH_ACK)
#define tcp_urg(t)  ((t)->th_flags & TH_URG)

/* Linux tcphdr bitfield → BSD macros */
#ifndef doff
# define doff      th_off
#endif

/* ipv4hdr field shims — macOS uses ip_* names */
#include <netinet/ip.h>

/* NLMSG constants */
#ifndef NLMSG_HDRLEN
# define NLMSG_HDRLEN   ((int)sizeof(struct nlmsghdr))
#endif
#ifndef NETLINK_ROUTE
# define NETLINK_ROUTE          0
# define NETLINK_UNUSED         1
# define NETLINK_USERSOCK       2
# define NETLINK_FIREWALL       3
# define NETLINK_NFLOG          5
# define NETLINK_XFRM           6
# define NETLINK_SELINUX        7
# define NETLINK_ISCSI          8
# define NETLINK_AUDIT          9
# define NETLINK_FIB_LOOKUP     10
# define NETLINK_CONNECTOR      11
# define NETLINK_NETFILTER      12
# define NETLINK_IP6_FW         13
# define NETLINK_DNRTMSG        14
# define NETLINK_KOBJECT_UEVENT 15
#endif

/* Additional netlink family constants */
#ifndef NETLINK_GENERIC
# define NETLINK_GENERIC       16
# define NETLINK_SCSITRANSPORT 18
# define NETLINK_ECRYPTFS      19
# define NETLINK_RDMA          20
#endif

/* RTM routing message types */
#ifndef RTM_NEWLINK
# define RTM_NEWLINK   16
# define RTM_DELLINK   17
# define RTM_GETLINK   18
# define RTM_SETLINK   19
# define RTM_NEWADDR   20
# define RTM_DELADDR   21
# define RTM_GETADDR   22
# define RTM_NEWROUTE  24
# define RTM_DELROUTE  25
# define RTM_GETROUTE  26
# define RTM_NEWNEIGH  28
# define RTM_DELNEIGH  29
# define RTM_GETNEIGH  30
# define RTM_NEWRULE   32
# define RTM_DELRULE   33
# define RTM_GETRULE   34
#endif

/* Additional RTM constants for tc / queueing */
#ifndef RTM_NEWQDISC
# define RTM_NEWQDISC      36
# define RTM_DELQDISC      37
# define RTM_GETQDISC      38
# define RTM_NEWTCLASS     40
# define RTM_DELTCLASS     41
# define RTM_GETTCLASS     42
# define RTM_NEWTFILTER    44
# define RTM_DELTFILTER    45
# define RTM_GETTFILTER    46
# define RTM_NEWACTION     48
# define RTM_DELACTION     49
# define RTM_GETACTION     50
# define RTM_NEWPREFIX     52
# define RTM_GETMULTICAST  58
# define RTM_GETANYCAST    62
# define RTM_NEWNEIGHTBL   64
# define RTM_GETNEIGHTBL   66
# define RTM_SETNEIGHTBL   67
# define RTM_NEWNDUSEROPT  68
# define RTM_NEWADDRLABEL  72
# define RTM_DELADDRLABEL  73
# define RTM_GETADDRLABEL  74
# define RTM_GETDCB        78
# define RTM_SETDCB        79
# define RTM_NEWNETCONF    80
# define RTM_GETNETCONF    82
# define RTM_NEWMDB        84
# define RTM_DELMDB        85
# define RTM_GETMDB        86
#endif
#endif /* LINUX_COMPAT_H */
