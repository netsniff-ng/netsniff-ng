#ifndef TRAFGEN_CONF
#define TRAFGEN_CONF

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>

#include "trafgen_proto.h"

#define PROTO_MAX_LAYERS	16

#define TYPE_INC	0
#define TYPE_DEC	1

enum csum {
	CSUM_IP,
	CSUM_UDP,
	CSUM_TCP,
	CSUM_UDP6,
	CSUM_TCP6,
	CSUM_ICMP6,
};

struct counter {
	int type, inc;
	uint8_t min, max, val;
	off_t off;
};

struct randomizer {
	off_t off;
};

struct csum16 {
	off_t off, from, to;
	enum csum which;
};

struct packet {
	uint32_t id;
	uint8_t *payload;
	size_t len;
	struct proto_hdr *headers[PROTO_MAX_LAYERS];
	size_t headers_count;
	struct timespec tstamp;
	bool is_created;
};

struct packet_dyn {
	struct counter *cnt;
	size_t clen;
	struct randomizer *rnd;
	size_t rlen;
	struct csum16 *csum;
	size_t slen;
	struct proto_field **fields;
	size_t flen;
};

static inline bool packet_dyn_has_elems(struct packet_dyn *p)
{
	return (p->clen || p->rlen || p->slen);
}

static inline bool packet_dyn_has_only_csums(struct packet_dyn *p)
{
	return (p->clen == 0 && p->rlen == 0 && p->slen);
}

static inline bool packet_dyn_has_fields(struct packet_dyn *p)
{
	return p->flen;
}

extern void compile_packets_str(char *str, bool verbose, unsigned int cpu);
extern void compile_packets(char *file, bool verbose, unsigned int cpu,
			    bool invoke_cpp, char *const cpp_argv[]);
extern void cleanup_packets(void);

extern void set_fill(uint8_t val, size_t len);

extern struct packet *current_packet(void);
extern uint32_t current_packet_id(void);
extern struct packet *packet_get(uint32_t id);
extern struct packet *realloc_packet(void);

#endif /* TRAFGEN_CONF */
