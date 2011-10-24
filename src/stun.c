/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "die.h"
#include "xmalloc.h"
#include "stun.h"
#include "timespec.h"

/* Discovery type result */
#define RESULT_NONE                   0
#define RESULT_OPEN_INTERNET          1
#define RESULT_FIREWALL_BLOCKS_UDP    2
#define RESULT_SYMMETRIC_UDP_FIREWALL 3
#define RESULT_FULL_CONE_NAT          4
#define RESULT_SYMMETRIC_NAT          5
#define RESULT_RESTRICTED_CONE_NAT    6
#define RESULT_PORT_RESTR_CONE_NAT    7

/* Message types */
#define BINDING_REQUEST               0x0001
#define BINDING_RESPONSE              0x0101
#define BINDING_ERROR_RESPONSE        0x0111
#define SHARED_SECRET_REQUEST         0x0002
#define SHARED_SECRET_RESPONSE        0x0102
#define SHARED_SECRET_ERROR_RESPONSE  0x0112

/* Attribute types */
#define MAPPED_ADDRESS                0x0001
#define RESPONSE_ADDRESS              0x0002
#define CHANGE_REQUEST                0x0003
#define SOURCE_ADDRESS                0x0004
#define CHANGED_ADDRESS               0x0005
#define USERNAME                      0x0006
#define PASSWORD                      0x0007
#define MESSAGE_INTEGRITY             0x0008
#define ERROR_CODE                    0x0009
#define UNKNOWN_ATTRIBUTES            0x000a
#define REFLECTED_FROM                0x000b

/* Error response codes */
#define ERROR_BAD_REQUEST             400
#define ERROR_UNAUTHORIZED            401
#define ERROR_UNKNOWN_ATTRIBUTE       420
#define ERROR_STALE_CREDENTIALS       430
#define ERROR_INTEGRITY_CHECK_FAIL    431
#define ERROR_MISSING_USERNAME        432
#define ERROR_USE_TLS                 433
#define ERROR_SERVER_ERROR            500
#define ERROR_GLOBAL_FAILURE          600

#define TIMEOUT                       1000
#define REQUEST_LEN                   20

#define ID_COOKIE_FIELD               htonl(((int) 'a' << 24) + \
					    ((int) 'c' << 16) + \
					    ((int) 'd' <<  8) + \
					     (int) 'c')

struct stun_header {
	uint16_t type;
	/*
	 * Message length is the count, in bytes, of the size of the
	 * message, not including the 20 byte header. (RFC-3489)
	 */
	uint16_t len;
	/*
	 * transid also serves as salt to randomize the request and the 
	 * response. All responses carry the same identifier as 
	 * the request they correspond to.
	 */
	/* For the new RFC this would be 0x2112A442 in network Byte order. */
	uint32_t magic_cookie; 
	uint32_t transid[3];
};

struct stun_attrib {
	uint16_t type;
	uint16_t len;
	uint8_t *value;
};

struct stun_mapped_addr {
	uint8_t none;
	uint8_t family;
	uint16_t port;
	uint32_t ip;
};

static int stun_test(const char *server_ip, uint16_t server_port,
		     uint16_t tun_port)
{
	int ret, sock, set = 1;
	uint8_t pkt[256];
	uint8_t rpkt[256];
	size_t len, off, max;
	struct in_addr in;
	struct timeval timeout;
	struct stun_header *hdr, *rhdr;
	struct stun_attrib *attr;
	struct stun_mapped_addr *addr;
	struct sockaddr_in saddr, daddr;
	fd_set fdset;

	if (!server_ip)
		return -EINVAL;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		panic("Cannot obtain socket!\n");

	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set));
	if (ret)
		panic("Cannot set socket option!\n");

	saddr.sin_family = PF_INET;
	saddr.sin_port = htons(tun_port);
	saddr.sin_addr.s_addr = INADDR_ANY;

	ret = bind(sock, (struct sockaddr *) &saddr, sizeof(saddr));
	if (ret)
		panic("Cannot bind udp socket!\n");

	len = REQUEST_LEN;
	hdr = (struct stun_header *) pkt;
	hdr->type = htons(BINDING_REQUEST);
	hdr->len = 0;
	hdr->magic_cookie = ID_COOKIE_FIELD;
	hdr->transid[0] = htonl(rand());
	hdr->transid[1] = htonl(rand());
	hdr->transid[2] = htonl(rand());

	daddr.sin_family = PF_INET;
	daddr.sin_port = htons(server_port);
	daddr.sin_addr.s_addr = inet_addr(server_ip);

	ret = sendto(sock, pkt, len, 0, (struct sockaddr *) &daddr,
		     sizeof(daddr));
	if (ret != len) {
		whine("Error sending request (%s)!\n", strerror(errno));
		return -EIO;
	}

	set_timeout(&timeout, TIMEOUT);

	FD_ZERO(&fdset);
	FD_SET(sock, &fdset);

	ret = select(sock + 1, &fdset, NULL, NULL, &timeout);
	if (ret <= 0) {
		whine("STUN server timeout!\n");
		return -EIO;
	}

	memset(rpkt, 0, sizeof(rpkt));
	len = read(sock, rpkt, sizeof(rpkt));

	close(sock);

	if (len < REQUEST_LEN) {
		whine("Bad STUN response (%s)!\n", strerror(errno));
		return -EIO;
	}

	rhdr = (struct stun_header *) rpkt;
	if (ntohs(rhdr->type) != BINDING_RESPONSE) {
		whine("Wrong STUN response type!\n");
		return -EIO;
	}

	if (rhdr->len == 0) {
		whine("No attributes in STUN response!\n");
		return -EIO;
	}

	if (rhdr->magic_cookie != hdr->magic_cookie ||
	    rhdr->transid[0] != hdr->transid[0] ||
	    rhdr->transid[1] != hdr->transid[1] ||
	    rhdr->transid[2] != hdr->transid[2]) {
		whine("Got wrong STUN transaction id!\n");
		return -EIO;
	}

	off = REQUEST_LEN;
	max = ntohs(rhdr->len) + REQUEST_LEN;

	while (off + 8 < max) {
		attr = (struct stun_attrib *) (rpkt + off);
		if (ntohs(attr->type) != MAPPED_ADDRESS)
			goto next;

		addr = (struct stun_mapped_addr *) (rpkt + off + 4);
		if (addr->family != 0x1)
			break;

		in.s_addr = addr->ip;
		info("Public mapping %s:%u!\n", inet_ntoa(in), ntohs(addr->port));
		break;
next:
		off += 4;
		off += ntohs(attr->len);
	}

	return 0;
}

void print_stun_probe(char *server, uint16_t sport, uint16_t tunport)
{
	char *address;
	struct hostent *hp;

	printf("STUN on %s:%u\n", server, sport);
	srand(time(NULL));
	hp = gethostbyname(server);
	if (!hp)
		return;
	address = inet_ntoa(*(struct in_addr *) hp->h_addr_list[0]);
	stun_test(address, sport, tunport);
}
