#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "irq.h"
#include "str.h"
#include "die.h"

int device_irq_number(const char *ifname)
{
	int irq = 0;
	char buff[128], sysname[128];
	FILE *fp;

	if (!strncmp("lo", ifname, strlen("lo")))
		return 0;

	slprintf(sysname, sizeof(sysname),
		 "/sys/class/net/%s/device/irq",
		 ifname);

	fp = fopen(sysname, "r");
	if (!fp)
		return -ENOENT;

	memset(buff, 0, sizeof(buff));

	if (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		irq = atoi(buff);
	}

	fclose(fp);
	return irq;
}

static char nic_irq_affinity_list[128];
static bool nic_irq_stored = false;
static int  nic_irq = -1;

static void device_save_irq_affinity_list(void)
{
	int ret, fd;
	char file[128];

	bug_on(nic_irq_stored);

	slprintf(file, sizeof(file),
		 "/proc/irq/%d/smp_affinity_list", nic_irq);

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return;

	memset(nic_irq_affinity_list, 0, sizeof(nic_irq_affinity_list));

	ret = read(fd, nic_irq_affinity_list,
		   sizeof(nic_irq_affinity_list));
	if (ret < 0)
		panic("Cannot store NIC IRQ affinity!\n");

	close(fd);

	nic_irq_stored = true;
}

void device_restore_irq_affinity_list(void)
{
	int ret, fd;
	char file[128];

	if (!nic_irq_stored)
		return;

	bug_on(nic_irq == -1);

	slprintf(file, sizeof(file),
		 "/proc/irq/%d/smp_affinity_list", nic_irq);

	fd = open(file, O_WRONLY);
	if (fd < 0)
		return;

	ret = write(fd, nic_irq_affinity_list,
		    sizeof(nic_irq_affinity_list));
	if (ret < 0)
		panic("Cannot restore NIC IRQ affinity!\n");

	close(fd);
}

int device_set_irq_affinity_list(int irq, unsigned long from, unsigned long to)
{
	int ret, fd;
	char file[128], list[64];

	if (unlikely(irq == 0))
		return 0;
	if (!nic_irq_stored) {
		nic_irq = irq;
		device_save_irq_affinity_list();
	}

	slprintf(file, sizeof(file), "/proc/irq/%d/smp_affinity_list", irq);
	slprintf(list, sizeof(list), "%lu-%lu\n", from, to);

	fd = open(file, O_WRONLY);
	if (fd < 0)
		return -ENOENT;

	ret = write(fd, list, strlen(list));

	close(fd);
	return ret;
}

int device_set_irq_affinity(int irq, unsigned long cpu)
{
	return device_set_irq_affinity_list(irq, cpu, cpu);
}
