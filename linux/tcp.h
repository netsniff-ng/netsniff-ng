#ifndef LINUX_TCP_H
#define LINUX_TCP_H
#include <netinet/tcp.h>
#ifndef TH_ECE
# define TH_ECE  0x40
# define TH_CWR  0x80
#endif
#ifndef TCP_CORK
# define TCP_CORK 3
#endif
#ifndef UDP_CORK
# define UDP_CORK 1
#endif
/* Map Linux field names to BSD names */
#define doff    th_off
#define fin     th_flags & TH_FIN
#endif
