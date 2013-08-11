#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "rnd.h"
#include "die.h"
#include "ioexact.h"
#include "ioops.h"

static int fdw = -1;

static void randombytes_weak(unsigned char *x, size_t xlen)
{
	int ret;

	if (fdw == -1) {
		for (;;) {
			fdw = open(LOW_ENTROPY_SOURCE, O_RDONLY);
			if (fdw != -1)
				break;
			sleep(1);
		}
	}

	while (xlen > 0) {
		if (xlen < 1048576)
			ret = xlen;
		else
			ret = 1048576;

		ret = read(fdw, x, ret);
		if (ret < 1) {
			sleep(1);
			continue;
		}

		x += ret;
		xlen -= ret;
	}
}

static void randombytes_strong(unsigned char *x, size_t xlen)
{
	int fds, ret;

	fds = open_or_die(HIG_ENTROPY_SOURCE, O_RDONLY);

	ret = read_exact(fds, x, xlen, 0);
	if (ret != (int) xlen)
		panic("Error reading from entropy source!\n");

	close(fds);
}

int secrand(void)
{
	int ret;

	randombytes_weak((void *) &ret, sizeof(ret));

	return ret;
}

void gen_key_bytes(unsigned char *area, size_t len)
{
	randombytes_strong(area, len);
}
