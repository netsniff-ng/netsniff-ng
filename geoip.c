#include <stddef.h>
#include <netinet/in.h>
/*
 * geoip.c - stubbed for macOS BPF port (GeoIP C API unavailable)
 */
#include "geoip.h"

void geoip4_lookup_info(struct sockaddr_in *sa, char **city,
                        char **region, float *lat, float *lon,
                        char **country, char **country_code3,
                        char **asname) {}
void geoip6_lookup_info(struct sockaddr_in6 *sa, char **city,
                        char **region, float *lat, float *lon,
                        char **country, char **country_code3,
                        char **asname) {}
void geoip4_init(void) {}
void geoip6_init(void) {}
void geoip4_cleanup(void) {}
void geoip6_cleanup(void) {}
