#ifndef GEOIPH_H
#define GEOIPH_H

#include <stdio.h>
#include <netinet/in.h>

#include "config.h"
#include "die.h"

#if defined(HAVE_GEOIP) && defined(HAVE_LIBZ)
extern void init_geoip(int enforce);
extern void update_geoip(void);
extern int geoip_working(void);
extern char *geoip4_city_name(struct sockaddr_in *sa);
extern char *geoip6_city_name(struct sockaddr_in6 *sa);
extern char *geoip4_region_name(struct sockaddr_in *sa);
extern char *geoip6_region_name(struct sockaddr_in6 *sa);
extern const char *geoip4_country_name(struct sockaddr_in *sa);
extern const char *geoip6_country_name(struct sockaddr_in6 *sa);
extern const char *geoip4_country_code3_name(struct sockaddr_in *sa);
extern const char *geoip6_country_code3_name(struct sockaddr_in6 *sa);
extern float geoip4_longitude(struct sockaddr_in *sa);
extern float geoip4_latitude(struct sockaddr_in *sa);
extern float geoip6_longitude(struct sockaddr_in6 *sa);
extern float geoip6_latitude(struct sockaddr_in6 *sa);
extern const char *geoip4_as_name(struct sockaddr_in *sa);
extern const char *geoip6_as_name(struct sockaddr_in6 *sa);
extern void destroy_geoip(void);
#else
static inline void init_geoip(int enforce)
{
}

static inline void destroy_geoip(void)
{
}

static inline void update_geoip(void)
{
	panic("No built-in geoip support!\n");
}

static inline int geoip_working(void)
{
	return 0;
}

static inline char *geoip4_city_name(struct sockaddr_in *sa)
{
	return NULL;
}

static inline char *geoip6_city_name(struct sockaddr_in6 *sa)
{
	return NULL;
}

static inline char *geoip4_region_name(struct sockaddr_in *sa)
{
	return NULL;
}

static inline char *geoip6_region_name(struct sockaddr_in6 *sa)
{
	return NULL;
}

static inline const char *geoip4_country_name(struct sockaddr_in *sa)
{
	return NULL;
}

static inline const char *geoip6_country_name(struct sockaddr_in6 *sa)
{
	return NULL;
}

static inline float geoip4_longitude(struct sockaddr_in *sa)
{
	return .0f;
}

static inline float geoip4_latitude(struct sockaddr_in *sa)
{
	return .0f;
}

static inline float geoip6_longitude(struct sockaddr_in6 *sa)
{
	return .0f;
}

static inline float geoip6_latitude(struct sockaddr_in6 *sa)
{
	return .0f;
}

static inline const char *geoip4_as_name(struct sockaddr_in *sa)
{
	return NULL;
}

static inline const char *geoip6_as_name(struct sockaddr_in6 *sa)
{
	return NULL;
}

static inline const char *geoip4_country_code3_name(struct sockaddr_in *sa)
{
	return NULL;
}

static inline const char *geoip6_country_code3_name(struct sockaddr_in6 *sa)
{
	return NULL;
}
#endif

#endif /* GEOIPH_H */
