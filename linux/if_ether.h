#ifndef LINUX_IF_ETHER_H
#define LINUX_IF_ETHER_H
#include <stdint.h>
#include <net/ethernet.h>
#define ETH_ALEN        6
#define ETH_HLEN        14
#define ETH_DATA_LEN    1500
#define ETH_FRAME_LEN   1514
#define ETH_P_IP        0x0800
#define ETH_P_IPV6      0x86DD
#define ETH_P_ARP       0x0806
#define ETH_P_8021Q     0x8100
#define ETH_P_MPLS_UC   0x8847
#define ETH_P_MPLS_MC   0x8848
#define ETH_P_ALL       0x0003
#define ETH_P_8021AD    0x88A8
#define ETH_P_LLDP      0x88CC
struct ethhdr {
    uint8_t  h_dest[ETH_ALEN];
    uint8_t  h_source[ETH_ALEN];
    uint16_t h_proto;
} __attribute__((packed));
#endif
