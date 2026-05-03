#ifndef WIRELESS_STUB_H
#define WIRELESS_STUB_H
#include <stdint.h>
#include <sys/socket.h>
#include <net/if.h>

#define SIOCGIWNAME  0x8B01
#define SIOCGIWRATE  0x8B21
#define SIOCGIWFREQ  0x8B05
#define SIOCGIWSTATS 0x8B0F
#define SIOCGIWRANGE 0x8B0B

struct iw_freq   { int32_t m; int16_t e; uint8_t i; uint8_t flags; };
struct iw_param  { int32_t value; uint8_t fixed; uint8_t disabled; uint16_t flags; };
struct iw_point  { void *pointer; uint16_t length; uint16_t flags; };
struct iw_quality { uint8_t qual; uint8_t level; uint8_t noise; uint8_t updated; };

struct iw_range {
    uint32_t     throughput;
    uint32_t     min_nwid;
    uint32_t     max_nwid;
    uint16_t     we_version_compiled;
    uint16_t     we_version_source;
    uint16_t     num_channels;
    uint8_t      num_frequency;
    uint32_t     event_capa[6];
    struct iw_quality max_qual;
};

union iwreq_data {
    char             name[IFNAMSIZ];
    struct iw_freq   freq;
    struct iw_param  bitrate;
    struct iw_point  data;
};

struct iwreq {
    char             ifr_name[IFNAMSIZ];
    union iwreq_data u;
};

struct iw_statistics {
    uint16_t          status;
    struct iw_quality qual;
    uint32_t          discard_nwid;
    uint32_t          discard_code;
    uint32_t          discard_fragment;
    uint32_t          discard_retries;
    uint32_t          miss_beacon;
};
#endif
