/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4  \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l80 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 *
 * Note: Your kernel has to be compiled with CONFIG_PACKET_MMAP=y option in 
 *       order to use this.
 */

/*
 * Contains: 
 *    Macros, defines and versioning stuff
 */

#ifndef _NET_MACROS_H_
#define _NET_MACROS_H_

/* Versioning information */
#define PROGNAME_STRING  "netsniff-ng"
#define VERSION_STRING   "0.5.5.0"

/*
 * Some versioning definition:
 * w.x.y.z 
 * `-+-+-+-- "Huge"  changes ---> These only change on overflow of "Minor"
 *   `-+-+-- "Major" changes _/            - x elem of {0, 1, ..., 9}
 *     `-+-- "Minor" changes, new features - y elem of {0, 1, ..., 9}
 *       `-- "Tiny"  changes, bug fixes    - z elem of {0, 1, ...}
 */

/* Stuff for compiler */
#define likely(x)               __builtin_expect((x), 1)
#define unlikely(x)             __builtin_expect((x), 0)

#define __read_mostly __attribute__((__section__(".data.read_mostly")))

/* Internals */
#define INTERVAL_COUNTER_REFR   1000	/* in ms */
#define INTERNAL_UDS_QUEUE_LEN  50	/* max AF_UNIX clients for accept */

#define POLL_WAIT_INF           -1	/* CPU friendly and appropriate for normal usage */
#define POLL_WAIT_NONE           0	/* This will pull CPU usage to 100 % */

#define BPF_BYPASS               1
#define BPF_NO_BYPASS            0

#define PROC_NO_HIGHPRIO         1

#define SYSD_ENABLE              1

/* TODO */
#define info(fmt, arg...)                                            \
                                fprintf(stderr, fmt, ## arg);

#define err(fmt, arg...)                                            \
                                fprintf(stderr, "E: " fmt, ## arg); \
                                fflush(stderr);

#define perr(fmt, arg...)                                           \
                                fprintf(stderr, "E: " fmt, ## arg); \
                                perror("");

#define DIV_KBYTES(x)           ((x) / (1024LLU))
#define DIV_MBYTES(x)           ((x) / (1048576LLU))
#define DIV_GBYTES(x)           ((x) / (1073741824LLU))

#define DIV_US2HOURS(x)         ((x) / (3600000000LLU))
#define MOD_HOURS2US(x)         ((x) % (3600000000LLU))
#define DIV_US2MINUT(x)         ((x) / (60000000LLU))
#define MOD_MINUT2US(x)         ((x) % (60000000LLU))
#define DIV_US2SECON(x)         ((x) / (1000000LLU))
#define MOD_SECON2US(x)         ((x) % (1000000LLU))
#define DIV_US2MILLI(x)         ((x) / (1000LLU))
#define MOD_MILLI2US(x)         ((x) % (1000LLU))

#define DIV_S2DAYS(x)           ((x) / (86400LLU))
#define MOD_DAYS2S(x)           ((x) % (86400LLU))
#define DIV_S2HOURS(x)          ((x) / (3600LLU))
#define MOD_HOURS2S(x)          ((x) % (3600LLU))
#define DIV_S2MINUT(x)          ((x) / (60LLU))
#define MOD_MINUT2S(x)          ((x) % (60LLU))

/* Release alias, some versioning fun ;) */
#define MOOH     "+------------------------+      \n" \
                 "| happy GNU year edition |      \n" \
                 "+------------------------+      \n" \
                 "        \\   ^__^               \n" \
                 "         \\  (oo)\\_______      \n" \
                 "            (__)\\       )\\/\\ \n" \
                 "                ||----w |       \n" \
                 "                ||     ||       \n"

#endif				/* _NET_MACROS_H_ */
