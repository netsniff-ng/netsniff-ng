#ifndef CURVETUN_H
#define CURVETUN_H

#include <unistd.h>

#define FILE_CLIENTS	".curvetun/clients"
#define FILE_SERVERS	".curvetun/servers"
#define FILE_PRIVKEY	".curvetun/priv.key"
#define FILE_PUBKEY	".curvetun/pub.key"
#define FILE_USERNAM	".curvetun/username"

#define LOCKFILE	"/var/run/curvetun.pid"

#define DEFAULT_KEY_LEN 64

#define PROTO_FLAG_EXIT	(1 << 0)
#define PROTO_FLAG_INIT	(1 << 1)

struct ct_proto {
        uint16_t payload;
        uint8_t flags;
}  __attribute__((packed));

/* FIXME: think up sth better */
#define TUNBUFF_SIZ	(3 * RUNTIME_PAGE_SIZE)
#define MAX_EPOLL_SIZE  10000
#define THREADS_PER_CPU 2

extern int server_main(char *home, char *dev, char *port, int udp,
		       int ipv4, int log);
extern int client_main(char *home, char *dev, char *host, char *port, int udp);

#define DEVNAME_SERVER	"curves0"
#define DEVNAME_CLIENT  "curvec0"

#endif /* CURVETUN_H */
