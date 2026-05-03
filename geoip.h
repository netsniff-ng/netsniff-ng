#ifndef GEOIP_H
#include <stddef.h>
#define GEOIP_H
typedef struct GeoIP { int dummy; } GeoIP;
typedef struct GeoIPRecord {
    const char *country_code;
    const char *country_name;
    const char *city;
    float latitude;
    float longitude;
} GeoIPRecord;
static inline GeoIP *GeoIP_open(const char *f, int flags) { return NULL; }
static inline void GeoIP_delete(GeoIP *g) {}
static inline GeoIPRecord *GeoIP_record_by_addr(GeoIP *g, const char *a) { return NULL; }
static inline void GeoIPRecord_delete(GeoIPRecord *r) {}
#define GEOIP_MEMORY_CACHE 1
#endif

/* Extended stub functions */
static inline int geoip_working(void) { return 0; }
static inline const char *geoip4_country_name(void *s) { return NULL; }
static inline const char *geoip6_country_name(void *s) { return NULL; }
static inline char *geoip4_region_name(void *s) { return NULL; }
static inline char *geoip6_region_name(void *s) { return NULL; }
static inline char *geoip4_city_name(void *s) { return NULL; }
static inline char *geoip6_city_name(void *s) { return NULL; }
static inline const char *geoip4_country_code3_name(void *s) { return NULL; }
static inline const char *geoip6_country_code3_name(void *s) { return NULL; }
static inline char *geoip4_asname(void *s) { return NULL; }
static inline char *geoip6_asname(void *s) { return NULL; }

/* Lifecycle stubs */
static inline void init_geoip(int enforce) { (void)enforce; }
static inline void update_geoip(void) {}
static inline void destroy_geoip(void) {}
