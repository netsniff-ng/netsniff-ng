#include <stdbool.h>

#include "taia.h"

static const struct taia tolerance_taia = {
	.sec.x = 0,
	.nano = 700000000ULL,	/* 700ms acceptance window */
	.atto = 0,
};

bool taia_looks_good(struct taia *arr_taia, struct taia *pkt_taia)
{
	bool good = false;
	struct taia tmp;

	if (taia_less(arr_taia, pkt_taia)) {
		taia_sub(&tmp, pkt_taia, arr_taia);
		if (taia_less(&tmp, &tolerance_taia))
			good = true;
	} else {
		taia_sub(&tmp, arr_taia, pkt_taia);
		if (taia_less(&tmp, &tolerance_taia))
			good = true;
	}

	return good;
}
