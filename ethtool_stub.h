/*
 * ethtool_stub.h - macOS stub for linux/ethtool.h
 */
#ifndef ETHTOOL_STUB_H
#define ETHTOOL_STUB_H

#include <stdint.h>

/* Minimal ethtool speed constants */
#define SPEED_10        10
#define SPEED_100       100
#define SPEED_1000      1000
#define SPEED_2500      2500
#define SPEED_5000      5000
#define SPEED_10000     10000
#define SPEED_25000     25000
#define SPEED_40000     40000
#define SPEED_100000    100000
#define SPEED_UNKNOWN   -1

/* Duplex */
#define DUPLEX_HALF     0x00
#define DUPLEX_FULL     0x01
#define DUPLEX_UNKNOWN  0xff

/* Port types */
#define PORT_TP         0x00
#define PORT_AUI        0x01
#define PORT_MII        0x02
#define PORT_FIBRE      0x03
#define PORT_BNC        0x04
#define PORT_OTHER      0xff

struct ethtool_cmd {
    uint32_t cmd;
    uint32_t supported;
    uint32_t advertising;
    uint16_t speed;
    uint8_t  duplex;
    uint8_t  port;
    uint8_t  phy_address;
    uint8_t  transceiver;
    uint8_t  autoneg;
    uint8_t  mdio_support;
    uint32_t maxtxpkt;
    uint32_t maxrxpkt;
    uint16_t speed_hi;
    uint8_t  eth_tp_mdix;
    uint8_t  eth_tp_mdix_ctrl;
    uint32_t lp_advertising;
    uint32_t reserved[2];
};

#define ETHTOOL_GSET    0x00000001
#define SIOCETHTOOL     0x8946

static inline uint32_t ethtool_cmd_speed(const struct ethtool_cmd *ep)
{
    return (ep->speed_hi << 16) | ep->speed;
}

#endif /* ETHTOOL_STUB_H */

struct ethtool_value {
    uint32_t cmd;
    uint32_t data;
};

#ifndef ETHTOOL_GLINK
# define ETHTOOL_GLINK 0x0000000a
#endif
