/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <GeoIP.h>
#include <GeoIPCity.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "built_in.h"
#include "die.h"
#include "ioops.h"
#include "str.h"
#include "xmalloc.h"
#include "zlib.h"
#include "geoip.h"

struct file {
	const char *desc, *local;
	const char *remote, *possible_prefix;
};

#define PRE	"/download/geoip/database"
static const struct file files[] = {
	[GEOIP_CITY_EDITION_REV1] = {
			.desc = "City IPv4",
			.local = PREFIX_STRING "/etc/netsniff-ng/city4.dat",
			.remote = "/GeoLiteCity.dat.gz",
			.possible_prefix = PRE,
		},
	[GEOIP_CITY_EDITION_REV1_V6] = {
			.desc = "City IPv6",
			.local = PREFIX_STRING "/etc/netsniff-ng/city6.dat",
			.remote = "/GeoLiteCityv6.dat.gz",
			.possible_prefix = PRE "/GeoLiteCityv6-beta",
		},
	[GEOIP_COUNTRY_EDITION] = {
			.desc = "Country IPv4",
			.local = PREFIX_STRING "/etc/netsniff-ng/country4.dat",
			.remote = "/GeoIP.dat.gz",
			.possible_prefix = PRE "/GeoLiteCountry",
		},
	[GEOIP_COUNTRY_EDITION_V6] = {
			.desc = "Country IPv6",
			.local = PREFIX_STRING "/etc/netsniff-ng/country6.dat",
			.remote = "/GeoIPv6.dat.gz",
			.possible_prefix = PRE,
		},
	[GEOIP_ASNUM_EDITION] = {
			.desc = "AS Numbers IPv4",
			.local = PREFIX_STRING "/etc/netsniff-ng/asname4.dat",
			.remote = "/GeoIPASNum.dat.gz",
			.possible_prefix = PRE "/asnum",
		},
	[GEOIP_ASNUM_EDITION_V6] = {
			.desc = "AS Numbers IPv6",
			.local = PREFIX_STRING "/etc/netsniff-ng/asname6.dat",
			.remote = "/GeoIPASNumv6.dat.gz",
			.possible_prefix = PRE "/asnum",
		},
};

static GeoIP *gi4_asname = NULL, *gi6_asname = NULL;
static GeoIP *gi4_country = NULL, *gi6_country = NULL;
static GeoIP *gi4_city = NULL, *gi6_city = NULL;

static GeoIPRecord empty = { 0 };

static char *servers[16] = { 0 };

#define CITYV4		(1 << 0)
#define CITYV6		(1 << 1)
#define COUNTRYV4	(1 << 2)
#define COUNTRYV6	(1 << 3)
#define ASNAMV4		(1 << 4)
#define ASNAMV6		(1 << 5)

#define HAVEALL		(CITYV4 | CITYV6 | COUNTRYV4 | COUNTRYV6 | ASNAMV4 | ASNAMV6)

static int geoip_db_present = 0;

int geoip_working(void)
{
	return geoip_db_present == HAVEALL;
}

static int geoip_get_remote_fd(const char *server, const char *port)
{
	int ret, fd = -1;
	struct addrinfo hints, *ahead, *ai;

	bug_on(!server || !port);

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICSERV;

	ret = getaddrinfo(server, port, &hints, &ahead);
	if (ret != 0)
		return -EIO;

	for (ai = ahead; ai != NULL && fd < 0; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;

		ret = connect(fd, ai->ai_addr, ai->ai_addrlen);
		if (ret < 0) {
			close(fd);
			fd = -1;
			continue;
		}

		break;
	}

	freeaddrinfo(ahead);

	return fd;
}

static void geoip_inflate(int which)
{
	int ret, ret2 = 1;
	gzFile fpi;
	FILE *fpo;
	char zfile[128], raw[4096];

	slprintf(zfile, sizeof(zfile), "%s.gz", files[which].local);
	fpi = gzopen(zfile, "rb");
	if (fpi == NULL)
		panic("No %s file!\n", zfile);

	fpo = fopen(files[which].local, "wb");
	if (fpo == NULL)
		panic("Cannot create %s!\n", files[which].local);

	while ((ret = gzread(fpi, raw, sizeof(raw))) && ret2)
		ret2 = fwrite(raw, ret, 1, fpo);

	gzclose(fpi);
	fclose(fpo);
}

static int geoip_get_database(const char *host, int which)
{
	int found, sock, fd, i, good, retry = 0;
	ssize_t ret, len, rtotlen = 0, totlen = 0;
	char raw[4096], *ptr, zfile[128];
	size_t lenl = strlen("Content-Length: ");
	size_t lent = strlen("HTTP/1.1 200 OK");
	size_t lenc = strlen("\r\n\r\n");

again:
	found = good = 0;
	ptr = NULL;
	len = 0;

	sock = geoip_get_remote_fd(host, "80");
	if (sock < 0)
		return -EIO;

	slprintf(raw, sizeof(raw), "GET %s%s HTTP/1.1\nHost: %s\r\n\r\n",
		 retry ? files[which].possible_prefix : "",
		 files[which].remote, host);

	ret = write(sock, raw, strlen(raw));
	if (ret <= 0) {
		close(sock);
		return -EIO;
	}

	shutdown(sock, SHUT_WR);

	slprintf(zfile, sizeof(zfile), "%s.gz", files[which].local);
	fd = open_or_die_m(zfile, O_WRONLY | O_CREAT | O_TRUNC, DEFFILEMODE);

	memset(raw, 0, sizeof(raw));
	ret = read(sock, raw, sizeof(raw));
	if (ret <= 0) {
		close(fd);
		close(sock);
		return -EIO;
	}

	raw[sizeof(raw) - 1] = 0;

	for (i = 0; i < ret; i++) {
		if (!strncmp(raw + i, "Content-Length: ", min_t(size_t, ret - i, lenl))) {
			ptr = raw + i + lenl;
			rtotlen = strtoul(ptr, NULL, 10);
		}

		if (!strncmp(raw + i, "HTTP/1.1 200 OK", min_t(size_t, ret - i, lent)))
			good = 1;

		if (!strncmp(raw + i, "\r\n\r\n", min_t(size_t, ret - i, lenc))) {
			ptr = raw + i + lenc;
			len = ret - i - lenc;
			found = 1;
			break;
		}
	}

	if (!found || ptr >= raw + ret || len < 0 || rtotlen == 0 || good == 0) {
		close(fd);
		close(sock);

		if (retry == 0) {
			retry = 1;
			goto again;
		}

		return -ENOENT;
	}

	do {
		write_or_die(fd, ptr, len);
		totlen += len;
		printf("\r%s [%.2f%%, %zd/%zd, %s]", files[which].desc,
		       100.f * totlen / rtotlen, totlen, rtotlen, host);
		fflush(stdout);

		memset(raw, 0, sizeof(raw));
		ret = read(sock, raw, sizeof(raw));

		ptr = raw;
		len = ret;
	} while(ret > 0);

	printf("\n");

	close(fd);
	close(sock);

	if (totlen != rtotlen) {
		unlink(files[which].local);
		return -EIO;
	}

	geoip_inflate(which);
	unlink(zfile);

	return 0;
}

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

const char *geoip4_as_name(struct sockaddr_in sa)
{
	bug_on(gi4_asname == NULL);

	return GeoIP_name_by_ipnum(gi4_asname, ntohl(sa.sin_addr.s_addr));
}

const char *geoip6_as_name(struct sockaddr_in6 sa)
{
	bug_on(gi6_asname == NULL);

	return GeoIP_name_by_ipnum_v6(gi6_asname, sa.sin6_addr);
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

static int fdout, fderr;

/* GeoIP people were too stupid to come to the idea that you could set
 * errno appropriately and return NULL instead of printing stuff from
 * the library directly that noone can turn off.
 */

static void geoip_open_prepare(void)
{
	fflush(stdout);
	fdout = dup_or_die(1);

	fflush(stderr);
	fderr = dup_or_die(2);

	close(1);
	close(2);
}

static void geoip_open_restore(void)
{
	dup2_or_die(fdout, 1);
	dup2_or_die(fderr, 2);

	close(fdout);
	close(fderr);
}

static GeoIP *geoip_open_type(int type, int flags)
{
	GeoIP *ret;

	geoip_open_prepare();
	ret = GeoIP_open_type(type, flags);
	geoip_open_restore();

	return ret;
}

static GeoIP *geoip_open(const char *filename, int flags)
{
	GeoIP *ret;

	geoip_open_prepare();
	ret = GeoIP_open(filename, flags);
	geoip_open_restore();

	return ret;
}

static void init_geoip_city_open4(int enforce)
{
	gi4_city = geoip_open(files[GEOIP_CITY_EDITION_REV1].local, GEOIP_MMAP_CACHE);
	if (gi4_city == NULL) {
		gi4_city = geoip_open_type(GEOIP_CITY_EDITION_REV1, GEOIP_MMAP_CACHE);
		if (gi4_city == NULL)
			if (enforce)
				panic("Cannot open GeoIP4 city database, try --update!\n");
	}

	if (gi4_city) {
		GeoIP_set_charset(gi4_city, GEOIP_CHARSET_UTF8);
		geoip_db_present |= CITYV4;
	}
}

static void init_geoip_city_open6(int enforce)
{
	gi6_city = geoip_open(files[GEOIP_CITY_EDITION_REV1_V6].local, GEOIP_MMAP_CACHE);
	if (gi6_city == NULL) {
		gi6_city = geoip_open_type(GEOIP_CITY_EDITION_REV1_V6, GEOIP_MMAP_CACHE);
		if (gi6_city == NULL)
			if (enforce)
				panic("Cannot open GeoIP6 city database, try --update!\n");
	}

	if (gi6_city) {
		GeoIP_set_charset(gi6_city, GEOIP_CHARSET_UTF8);
		geoip_db_present |= CITYV6;
	}
}

static void init_geoip_city(int enforce)
{
	init_geoip_city_open4(enforce);
	init_geoip_city_open6(enforce);
}

static void destroy_geoip_city(void)
{
	GeoIP_delete(gi4_city);
	GeoIP_delete(gi6_city);
}

static void init_geoip_country_open4(int enforce)
{
	gi4_country = geoip_open(files[GEOIP_COUNTRY_EDITION].local, GEOIP_MMAP_CACHE);
	if (gi4_country == NULL) {
		gi4_country = geoip_open_type(GEOIP_COUNTRY_EDITION, GEOIP_MMAP_CACHE);
		if (gi4_country == NULL)
			if (enforce)
				panic("Cannot open GeoIP4 country database, try --update!\n");
	}

	if (gi4_country) {
		GeoIP_set_charset(gi4_country, GEOIP_CHARSET_UTF8);
		geoip_db_present |= COUNTRYV4;
	}
}

static void init_geoip_country_open6(int enforce)
{
	gi6_country = geoip_open(files[GEOIP_COUNTRY_EDITION_V6].local, GEOIP_MMAP_CACHE);
	if (gi6_country == NULL) {
		gi6_country = geoip_open_type(GEOIP_COUNTRY_EDITION_V6, GEOIP_MMAP_CACHE);
		if (gi6_country == NULL)
			if (enforce)
				panic("Cannot open GeoIP6 country database, try --update!\n");
	}

	if (gi6_country) {
		GeoIP_set_charset(gi6_country, GEOIP_CHARSET_UTF8);
		geoip_db_present |= COUNTRYV6;
	}
}

static void init_geoip_country(int enforce)
{
	init_geoip_country_open4(enforce);
	init_geoip_country_open6(enforce);
}

static void destroy_geoip_country(void)
{
	GeoIP_delete(gi4_country);
	GeoIP_delete(gi6_country);
}

static void init_geoip_asname_open4(int enforce)
{
	gi4_asname = geoip_open(files[GEOIP_ASNUM_EDITION].local, GEOIP_MMAP_CACHE);
	if (gi4_asname == NULL) {
		gi4_asname = geoip_open_type(GEOIP_ASNUM_EDITION, GEOIP_MMAP_CACHE);
		if (gi4_asname == NULL)
			if (enforce)
				panic("Cannot open GeoIP4 AS database, try --update!\n");
	}

	if (gi4_asname) {
		GeoIP_set_charset(gi4_asname, GEOIP_CHARSET_UTF8);
		geoip_db_present |= ASNAMV4;
	}
}

static void init_geoip_asname_open6(int enforce)
{
	gi6_asname = geoip_open(files[GEOIP_ASNUM_EDITION_V6].local, GEOIP_MMAP_CACHE);
	if (gi6_asname == NULL) {
		gi6_asname = geoip_open_type(GEOIP_ASNUM_EDITION_V6, GEOIP_MMAP_CACHE);
		if (gi6_asname == NULL)
			if (enforce)
				panic("Cannot open GeoIP6 AS database, try --update!\n");
	}

	if (gi6_asname) {
		GeoIP_set_charset(gi6_asname, GEOIP_CHARSET_UTF8);
		geoip_db_present |= ASNAMV6;
	}
}

static void init_geoip_asname(int enforce)
{
	init_geoip_asname_open4(enforce);
	init_geoip_asname_open6(enforce);
}

static void destroy_geoip_asname(void)
{
	GeoIP_delete(gi4_asname);
	GeoIP_delete(gi6_asname);
}

static void init_mirrors(void)
{
	size_t i = 0;
	FILE *fp;
	char buff[256];

	fp = fopen(PREFIX_STRING "/etc/netsniff-ng/geoip.conf", "r");
	if (!fp)
		panic("Cannot open geoip.conf!\n");

	fmemset(buff, 0, sizeof(buff));
	while (fgets(buff, sizeof(buff), fp) != NULL &&
	       i < array_size(servers)) {
		buff[sizeof(buff) - 1] = 0;
		buff[strlen(buff) - 1] = 0;

		if (buff[0] == '#') {
			fmemset(buff, 0, sizeof(buff));
			continue;
		}

		servers[i++] = xstrdup(buff);
		fmemset(buff, 0, sizeof(buff));
	}

	fclose(fp);
}

static void destroy_mirrors(void)
{
	size_t i;

	for (i = 0; i < array_size(servers); ++i)
		free(servers[i]);
}

void init_geoip(int enforce)
{
	init_geoip_city(enforce);
	init_geoip_country(enforce);
	init_geoip_asname(enforce);
}

void update_geoip(void)
{
	size_t i, j;
	int ret, good = 0;

	init_mirrors();

	for (i = 0; i < array_size(files); ++i) {
		if (files[i].local && files[i].remote) {
			good = 0;

			for (j = 0; j < array_size(servers); ++j) {
				if (servers[j] == NULL)
					continue;
				ret = geoip_get_database(servers[j], i);
				if (!ret) {
					good = 1;
					break;
				}
			}

			if (good == 0)
				panic("Cannot get %s from mirrors!\n",
				      files[i].remote);
		}
	}

	destroy_mirrors();
}

void destroy_geoip(void)
{
	destroy_geoip_city();
	destroy_geoip_country();
	destroy_geoip_asname();

	geoip_db_present = 0;
}
