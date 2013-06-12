#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "xmalloc.h"
#include "die.h"
#include "sock.h"
#include "stun.h"

#define BINDING_REQUEST               0x0001
#define BINDING_RESPONSE              0x0101

#define MAPPED_ADDRESS                0x0001

#define TIMEOUT                       5000
#define REQUEST_LEN                   20

#define ID_COOKIE_FIELD               htonl(((int) 'a' << 24) + \
					    ((int) 'c' << 16) + \
					    ((int) 'd' <<  8) + \
					     (int) 'c')

struct stun_header {
	uint16_t type;
	uint16_t len;
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

static int stun_test(const char *server_ip, int server_port,
		     int tun_port)
{
	int ret, sock;
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

	set_reuseaddr(sock);

	memset(&saddr, 0, sizeof(saddr));
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
		printf("Error sending request (%s)!\n", strerror(errno));
		goto close_error;
	}

	timeout.tv_sec = TIMEOUT / 1000;
	timeout.tv_usec = (TIMEOUT % 1000) * 1000;

	FD_ZERO(&fdset);
	FD_SET(sock, &fdset);

	ret = select(sock + 1, &fdset, NULL, NULL, &timeout);
	if (ret <= 0) {
		printf("STUN server timeout!\n");
		goto close_error;
	}

	memset(rpkt, 0, sizeof(rpkt));
	len = read(sock, rpkt, sizeof(rpkt));

	close(sock);

	if (len < REQUEST_LEN) {
		printf("Bad STUN response (%s)!\n", strerror(errno));
		return -EIO;
	}

	rhdr = (struct stun_header *) rpkt;
	if (ntohs(rhdr->type) != BINDING_RESPONSE) {
		printf("Wrong STUN response type!\n");
		return -EIO;
	}

	if (rhdr->len == 0) {
		printf("No attributes in STUN response!\n");
		return -EIO;
	}

	if (rhdr->magic_cookie != hdr->magic_cookie ||
	    rhdr->transid[0] != hdr->transid[0] ||
	    rhdr->transid[1] != hdr->transid[1] ||
	    rhdr->transid[2] != hdr->transid[2]) {
		printf("Got wrong STUN transaction id!\n");
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
		printf("Public mapping %s:%u!\n",
		       inet_ntoa(in), ntohs(addr->port));
		break;
next:
		off += 4;
		off += ntohs(attr->len);
	}

	return 0;
close_error:
	close(sock);
	return -EIO;
}

int print_stun_probe(char *server, int sport, int tport)
{
	char *address;
	struct hostent *hp;

	printf("STUN on %s:%u\n", server, sport);

	srand(time(NULL));
	hp = gethostbyname(server);
	if (!hp)
		return -EIO;
	address = inet_ntoa(*(struct in_addr *) hp->h_addr_list[0]);
	return stun_test(address, sport, tport);
}
