/*
 * Encapsulating Security Payload described in RFC4303
 * programmed by Markus Amend 2012 as a contribution to
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend.
 * Subject to the GPL, version 2.
 */

#ifndef ESP_H
#define ESP_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"

struct esphdr {
	uint32_t h_spi;
	uint32_t h_sn;
} __attribute__((packed));

static inline void esp(uint8_t *packet, size_t len)
{
	struct esphdr *esp = (struct esphdr *) packet;

	if (len < sizeof(struct esphdr))
		return;

	tprintf(" [ ESP ");
	tprintf("SPI (0x%x), ", ntohl(esp->h_spi));
	tprintf("SN (0x%x)", ntohl(esp->h_sn));
	tprintf(" ]\n");
}

static inline void esp_less(uint8_t *packet, size_t len)
{
	if (len < sizeof(struct esphdr))
		return;

	tprintf(" ESP");
}

static inline void esp_next(uint8_t *packet, size_t len,
			     struct hash_table **table,
			     unsigned int *key, size_t *off)
{
	if (len < sizeof(struct esphdr))
		return;
	(*off) = sizeof(struct esphdr);
	(*key) = 0;
	(*table) = NULL;
}

struct protocol esp_ops = {
	.key = 0x32,
	.print_full = esp,
	.print_less = esp_less,
	.print_pay_ascii = empty,
	.print_pay_hex = empty,
	.print_pay_none = esp,
	.print_all_cstyle = __hex2,
	.print_all_hex = __hex,
	.proto_next = esp_next,
};

#endif /* ESP_H */
