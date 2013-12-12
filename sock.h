#ifndef SOCK_H
#define SOCK_H

extern int af_socket(int af);
extern int pf_socket(void);
extern int pf_tx_socket(void);
extern void set_nonblocking(int fd);
extern int set_nonblocking_sloppy(int fd);
extern int set_reuseaddr(int fd);
extern void set_sock_qdisc_bypass(int fd, int verbose);
extern void set_sock_prio(int fd, int prio);
extern void set_tcp_nodelay(int fd);
extern void set_socket_keepalive(int fd);
extern int set_ipv6_only(int fd);
extern void set_mtu_disc_dont(int fd);
extern void set_system_socket_memory(int *vals, size_t len);
extern void reset_system_socket_memory(int *vals, size_t len);

#endif /* SOCK_H */
