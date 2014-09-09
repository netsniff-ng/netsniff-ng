#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>

#include "sock.h"
#include "die.h"
#include "str.h"
#include "built_in.h"

int af_socket(int af)
{
	int sock;

	if (unlikely(af != AF_INET && af != AF_INET6))
		panic("Wrong AF socket type!\n");

	sock = socket(af, SOCK_DGRAM, 0);
	if (unlikely(sock < 0))
		panic("Creation AF socket failed!\n");

	return sock;
}

int pf_socket(void)
{
	int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (unlikely(sock < 0))
		panic("Creation of PF socket failed!\n");

	return sock;
}

int pf_tx_socket(void)
{
	int sock = socket(PF_PACKET, SOCK_RAW, 0);
	if (unlikely(sock < 0))
		panic("Creation of PF TX socket failed!\n");

	return sock;
}

/* Avail in kernel >= 3.14
 * in commit d346a3fae3 (packet: introduce PACKET_QDISC_BYPASS socket option)
 */
void set_sock_qdisc_bypass(int fd, int verbose)
{
	int ret, val = 1;

	ret = setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &val, sizeof(val));
	if (ret < 0) {
		if (errno == ENOPROTOOPT) {
			if (verbose)
				printf("No kernel support for PACKET_QDISC_BYPASS"
				       " (kernel < 3.14?)\n");
		} else
			perror("Cannot set PACKET_QDISC_BYPASS");
	} else
		if (verbose) printf("Enabled kernel qdisc bypass\n");
}

void set_sock_prio(int fd, int prio)
{
	int ret, val = prio;

	ret = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &val, sizeof(val));
	if (unlikely(ret))
		panic("Cannot set socket priority!\n");
}

void set_nonblocking(int fd)
{
	int ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFD, 0) | O_NONBLOCK);
	if (unlikely(ret < 0))
		panic("Cannot fcntl!\n");
}

int set_nonblocking_sloppy(int fd)
{
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFD, 0) | O_NONBLOCK);
}

void set_socket_keepalive(int fd)
{
	int ret, one = 1;

	ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
	if (unlikely(ret))
		panic("Cannot set TCP keepalive!\n");
}

void set_tcp_nodelay(int fd)
{
	int ret, one = 1;

	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (unlikely(ret))
		panic("Cannot set TCP nodelay!\n");
}

int set_ipv6_only(int fd)
{
	int one = 1;
	return setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
}

int set_reuseaddr(int fd)
{
	int ret, one = 1;

	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (unlikely(ret < 0))
		panic("Cannot reuse addr!\n");

	return 0;
}

void set_mtu_disc_dont(int fd)
{
	int mtu = IP_PMTUDISC_DONT, ret;

	ret = setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu));
	if (unlikely(ret))
		panic("Cannot set MTU discovery options!\n");
}

enum {
	sock_rmem_max = 0,
	sock_rmem_def,
	sock_wmem_max,
	sock_wmem_def,
};

#define SMEM_SUG_MAX	104857600
#define SMEM_SUG_DEF	4194304

static const char *const sock_mem[] = {
	[sock_rmem_max] = "/proc/sys/net/core/rmem_max",
	[sock_rmem_def] = "/proc/sys/net/core/rmem_default",
	[sock_wmem_max] = "/proc/sys/net/core/wmem_max",
	[sock_wmem_def] = "/proc/sys/net/core/wmem_default",
};

static int get_system_socket_mem(int which)
{
	int fd, val = -1;
	ssize_t ret;
	const char *file = sock_mem[which];
	char buff[64];

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return val;

	ret = read(fd, buff, sizeof(buff));
	if (ret > 0)
		val = atoi(buff);

	close(fd);
	return val;
}

static void set_system_socket_mem(int which, int val)
{
	int fd;
	const char *file = sock_mem[which];
	ssize_t ret;
	char buff[64];

	fd = open(file, O_WRONLY);
	if (fd < 0)
		return;

	memset(buff, 0, sizeof(buff));
	slprintf(buff, sizeof(buff), "%d", val);

	ret = write(fd, buff, strlen(buff));
	if (ret < 0)
		panic("Cannot set system socket memory!\n");

	close(fd);
}

void set_system_socket_memory(int *vals, size_t len)
{
	bug_on(len != 4);

	if ((vals[0] = get_system_socket_mem(sock_rmem_max)) < SMEM_SUG_MAX)
		set_system_socket_mem(sock_rmem_max, SMEM_SUG_MAX);
	if ((vals[1] = get_system_socket_mem(sock_rmem_def)) < SMEM_SUG_DEF)
		set_system_socket_mem(sock_rmem_def, SMEM_SUG_DEF);
	if ((vals[2] = get_system_socket_mem(sock_wmem_max)) < SMEM_SUG_MAX)
		set_system_socket_mem(sock_wmem_max, SMEM_SUG_MAX);
	if ((vals[3] = get_system_socket_mem(sock_wmem_def)) < SMEM_SUG_DEF)
		set_system_socket_mem(sock_wmem_def, SMEM_SUG_DEF);
}

void reset_system_socket_memory(int *vals, size_t len)
{
	bug_on(len != 4);

	set_system_socket_mem(sock_rmem_max, vals[0]);
	set_system_socket_mem(sock_rmem_def, vals[1]);
	set_system_socket_mem(sock_wmem_max, vals[2]);
	set_system_socket_mem(sock_wmem_def, vals[3]);
}
