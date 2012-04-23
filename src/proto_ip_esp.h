/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>
 * Subject to the GPL, version 2.
 *
 * Encapsulating Security Payload described in RFC4303
 */

#ifndef PROTO_ESP_H
#define PROTO_ESP_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"
#include "built_in.h"

struct esp_hdr {
	uint32_t h_spi;
	uint32_t h_sn;
} __packed;

static inline void esp(struct pkt_buff *pkt)
{
	struct esp_hdr *esp_ops;

	esp_ops = (struct esp_hdr *) pkt_pull(pkt, sizeof(*esp_ops));
	if (esp_ops == NULL)
		return;

	tprintf(" [ ESP ");
	tprintf("SPI (0x%x), ", ntohl(esp_ops->h_spi));
	tprintf("SN (0x%x)", ntohl(esp_ops->h_sn));
	tprintf(" ]\n");
}

static inline void esp_less(struct pkt_buff *pkt)
{
	struct esp_hdr *esp_ops;

	esp_ops = (struct esp_hdr *) pkt_pull(pkt, sizeof(*esp_ops));
	if (esp_ops == NULL)
		return;

	tprintf(" ESP");
}

struct protocol ip_esp_ops = {
	.key = 0x32,
	.print_full = esp,
	.print_less = esp_less,
};

#endif /* PROTO_ESP_H */
