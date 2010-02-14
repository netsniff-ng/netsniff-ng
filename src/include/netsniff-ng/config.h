#ifndef	__NET_CONFIG_H__
#define	__NET_CONFIG_H__

#include <netsniff-ng/types.h>
#include <netsniff-ng/print.h>

/* Internals */
#define DEFAULT_INTERFACE "lo"
#define INTERVAL_COUNTER_REFR   1000	/* in ms */

#define POLL_WAIT_INF           -1	/* CPU friendly and appropriate for normal usage */
#define POLL_WAIT_NONE           0	/* This will pull CPU usage to 100 % */

#define BPF_BYPASS               1
#define BPF_NO_BYPASS            0

#define PROC_NO_HIGHPRIO         1

#define SYSD_ENABLE              1

#define PACKET_DONT_CARE        -1

typedef struct system_data {
	/* Some more or less boolean conf values */
	int sysdaemon;
	int blocking_mode;
	int no_prioritization;
	int bypass_bpf;
	int packet_type;
	/* Daemon mode settings */
	char *pidfile;
	/* Berkeley Packet Filter rules */
	char *rulefile;
	/* Ethernet device */
	char *dev;
	FILE *dump_pcap;
	void (*print_pkt) (ring_buff_bytes_t *, const struct tpacket_hdr *);
} system_data_t;

extern void init_configuration(system_data_t * config);
extern void set_configuration(int argc, char **argv, system_data_t * sd);
extern void check_config(system_data_t * sd);
#endif				/* __NET_CONFIG_H__ */
