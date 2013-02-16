/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <GeoIP.h>
#include <GeoIPCity.h>
#include <netinet/in.h>

#include "built_in.h"
#include "die.h"
#include "geoip.h"

static GeoIP *gi4_country = NULL, *gi6_country = NULL;
static GeoIP *gi4_city = NULL, *gi6_city = NULL;

static GeoIPRecord empty = { 0 };

#define COUNTRY4_PATH	"/etc/netsniff-ng/country4.dat"
#define COUNTRY6_PATH	"/etc/netsniff-ng/country6.dat"

#define CITY4_PATH	"/etc/netsniff-ng/city4.dat"
#define CITY6_PATH	"/etc/netsniff-ng/city6.dat"

static GeoIPRecord *geoip4_get_record(struct sockaddr_in sa)
{
	bug_on(gi4_city == NULL);

	return GeoIP_record_by_ipnum(gi4_city, ntohl(sa.sin_addr.s_addr)) ? : &empty;
}

static GeoIPRecord *geoip6_get_record(struct sockaddr_in6 sa)
{
	bug_on(gi6_city == NULL);

	return GeoIP_record_by_ipnum_v6(gi6_city, sa.sin6_addr) ? : &empty;
}

float geoip4_longitude(struct sockaddr_in sa)
{
	return geoip4_get_record(sa)->longitude;
}

float geoip4_latitude(struct sockaddr_in sa)
{
	return geoip4_get_record(sa)->latitude;
}

float geoip6_longitude(struct sockaddr_in6 sa)
{
	return geoip6_get_record(sa)->longitude;
}

float geoip6_latitude(struct sockaddr_in6 sa)
{
	return geoip6_get_record(sa)->latitude;
}

const char *geoip4_city_name(struct sockaddr_in sa)
{
	return geoip4_get_record(sa)->city;
}

const char *geoip6_city_name(struct sockaddr_in6 sa)
{
	return geoip6_get_record(sa)->city;
}

const char *geoip4_region_name(struct sockaddr_in sa)
{
	return geoip4_get_record(sa)->region;
}

const char *geoip6_region_name(struct sockaddr_in6 sa)
{
	return geoip6_get_record(sa)->region;
}

const char *geoip4_country_name(struct sockaddr_in sa)
{
	bug_on(gi4_country == NULL);

	return GeoIP_country_name_by_ipnum(gi4_country, ntohl(sa.sin_addr.s_addr));
}

const char *geoip6_country_name(struct sockaddr_in6 sa)
{
	bug_on(gi6_country == NULL);

	return GeoIP_country_name_by_ipnum_v6(gi6_country, sa.sin6_addr);
}

static void init_geoip_city_open4(void)
{
	gi4_city = GeoIP_open_type(GEOIP_CITY_EDITION_REV1, GEOIP_MMAP_CACHE);
	if (gi4_city == NULL) {
		gi4_city = GeoIP_open(CITY4_PATH, GEOIP_MMAP_CACHE);
		if (gi4_city == NULL)
			panic("Cannot open GeoIP4 city database!\n");
	}

	GeoIP_set_charset(gi4_city, GEOIP_CHARSET_UTF8);
}

static void init_geoip_city_open6(void)
{
	gi6_city = GeoIP_open_type(GEOIP_CITY_EDITION_REV1_V6, GEOIP_MMAP_CACHE);
	if (gi6_city == NULL) {
		gi6_city = GeoIP_open(CITY6_PATH, GEOIP_MMAP_CACHE);
		if (gi6_city == NULL)
			panic("Cannot open GeoIP6 city database!\n");
	}

	GeoIP_set_charset(gi6_city, GEOIP_CHARSET_UTF8);
}

static void init_geoip_city(void)
{
	init_geoip_city_open4();
	init_geoip_city_open6();
}

static void init_geoip_country_open4(void)
{
	gi4_country = GeoIP_open_type(GEOIP_COUNTRY_EDITION, GEOIP_MMAP_CACHE);
	if (gi4_country == NULL) {
		gi4_country = GeoIP_open(COUNTRY4_PATH, GEOIP_MMAP_CACHE);
		if (gi4_country == NULL)
			panic("Cannot open GeoIP4 country database!\n");
	}

	GeoIP_set_charset(gi4_country, GEOIP_CHARSET_UTF8);
}

static void init_geoip_country_open6(void)
{
	gi6_country = GeoIP_open_type(GEOIP_COUNTRY_EDITION_V6, GEOIP_MMAP_CACHE);
	if (gi6_country == NULL) {
		gi6_country = GeoIP_open(COUNTRY6_PATH, GEOIP_MMAP_CACHE);
		if (gi6_country == NULL)
			panic("Cannot open GeoIP6 country database!\n");
	}

	GeoIP_set_charset(gi6_country, GEOIP_CHARSET_UTF8);
}

static void init_geoip_country(void)
{
	init_geoip_country_open4();
	init_geoip_country_open6();
}

static void destroy_geoip_city(void)
{
	GeoIP_delete(gi4_city);
	GeoIP_delete(gi6_city);
}

static void destroy_geoip_country(void)
{
	GeoIP_delete(gi4_country);
	GeoIP_delete(gi6_country);
}

void init_geoip(void)
{
	init_geoip_city();
	init_geoip_country();
}

void destroy_geoip(void)
{
	destroy_geoip_city();
	destroy_geoip_country();
}
