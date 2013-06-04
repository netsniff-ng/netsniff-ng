#ifndef GEOIPH_H
#define GEOIPH_H

#include <netinet/in.h>

extern void init_geoip(int enforce);
extern void update_geoip(void);
extern int geoip_working(void);
extern const char *geoip4_city_name(struct sockaddr_in sa);
extern const char *geoip6_city_name(struct sockaddr_in6 sa);
extern const char *geoip4_region_name(struct sockaddr_in sa);
extern const char *geoip6_region_name(struct sockaddr_in6 sa);
extern const char *geoip4_country_name(struct sockaddr_in sa);
extern const char *geoip6_country_name(struct sockaddr_in6 sa);
extern float geoip4_longitude(struct sockaddr_in sa);
extern float geoip4_latitude(struct sockaddr_in sa);
extern float geoip6_longitude(struct sockaddr_in6 sa);
extern float geoip6_latitude(struct sockaddr_in6 sa);
extern const char *geoip4_as_name(struct sockaddr_in sa);
extern const char *geoip6_as_name(struct sockaddr_in6 sa);
extern void destroy_geoip(void);

#endif /* GEOIPH_H */
