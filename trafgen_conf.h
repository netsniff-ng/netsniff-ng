#ifndef TRAFGEN_CONF
#define TRAFGEN_CONF

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#define TYPE_INC	0
#define TYPE_DEC	1

enum csum {
	CSUM_IP,
	CSUM_UDP,
	CSUM_TCP,
	CSUM_UDP6,
	CSUM_TCP6,
};

struct counter {
	int type;
	uint8_t min, max, inc, val;
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
	uint8_t *payload;
	size_t len;
};

struct packet_dyn {
	struct counter *cnt;
	size_t clen;
	struct randomizer *rnd;
	size_t rlen;
	struct csum16 *csum;
	size_t slen;
};

static inline bool packet_dyn_has_elems(struct packet_dyn *p)
{
	return (p->clen || p->rlen || p->slen);
}

static inline bool packet_dyn_has_only_csums(struct packet_dyn *p)
{
	return (p->clen == 0 && p->rlen == 0 && p->slen);
}

extern void compile_packets(char *file, bool verbose, unsigned int cpu, bool invoke_cpp);
extern void cleanup_packets(void);

#endif /* TRAFGEN_CONF */
