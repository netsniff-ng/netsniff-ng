/*
 * curvetun - the cipherspace wormhole creator
 * Part of the netsniff-ng project
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "xmalloc.h"
#include "netdev.h"
#include "version.h"
#include "stun.h"
#include "die.h"
#include "strlcpy.h"
#include "signals.h"
#include "curvetun.h"

enum working_mode {
	MODE_UNKNOW,
	MODE_KEYGEN,
	MODE_CLIENT,
	MODE_SERVER,
};

sig_atomic_t sigint = 0;

static char *home = NULL;

static const char *short_options = "kcsvhp:t:d:u";

static struct option long_options[] = {
	{"client", optional_argument, 0, 'c'},
	{"dev", required_argument, 0, 'd'},
	{"port", required_argument, 0, 'p'},
	{"stun", required_argument, 0, 't'},
	{"keygen", no_argument, 0, 'k'},
	{"server", no_argument, 0, 's'},
	{"udp", no_argument, 0, 'u'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
		sigint = 1;
		break;
	case SIGHUP:
		break;
	default:
		break;
	}
}

static void header(void)
{
	printf("%s%s%s\n", colorize_start(bold), "curvetun "
	       VERSION_STRING, colorize_end());
}

static void help(void)
{
	printf("\ncurvetun %s, curve25519-based multiuser IP tunnel\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: curvetun [options]\n");
	printf("Options:\n");
	printf("  -k|--keygen             Generate public/private keypair\n");
	printf("  -d|--dev <tun>          Networking tunnel device, e.g. tun0\n");
	printf(" Client settings:\n");
	printf("  -c|--client[=alias]     Client mode, server alias optional\n");
	printf(" Server settings:\n");
	printf("  -s|--server             Server mode\n");
	printf("  -p|--port <num>         Port number (mandatory)\n");
	printf("  -t|--stun <server>      Show public IP/Port mapping via STUN\n");
	printf("  -u|--udp                Use UDP as carrier instead of TCP\n");
	printf(" Misc:\n");
	printf("  -v|--version            Print version\n");
	printf("  -h|--help               Print this help\n");
	printf("\n");
	printf("Example:\n");
	printf("  A. Keygen example:\n");
	printf("      1. curvetun --keygen\n");
	printf("      2. Now the following files are done setting up:\n");
	printf("           ~/.curvetun/priv.key - Your private key\n");
	printf("           ~/.curvetun/pub.key  - Your public key\n");
	printf("           ~/.curvetun/username - Your username\n");
	printf("  B. Server:\n");
	printf("      1. curvetun --server --port 6666 --stun stunserver.org\n");
	printf("      2. ifconfig curve-s up\n");
	printf("      2. ifconfig curve-s 10.0.0.1/24\n");
	printf("      3. (setup route)\n");
	printf("  C. Client:\n");
	printf("      1. curvetun --client --mode random\n");
	printf("      2. ifconfig curve-c up\n");
	printf("      2. ifconfig curve-s 10.0.0.2/24\n");
	printf("      3. (setup route)\n");
	printf("  Where both participants have the following files specified:\n");
	printf("   ~/.curvetun/clients - Participants the server accepts\n");
	printf("        line-format:   username;pubkey\n");
	printf("   ~/.curvetun/servers - Possible servers the client can connect to\n");
	printf("        line-format:   alias;serverip|servername;port;pubkey\n");
	printf("\n");
	printf("Note:\n");
	printf("  There is no default port specified, so that users are forced\n");
	printf("  to select their own!\n");
	printf("\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	die();
}

static void version(void)
{
	printf("\ncurvetun %s, curve25519-based multiuser IP tunnel\n",
               VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	die();
}

static void check_file_or_die(char *home, char *file)
{
	char path[512];
	struct stat st;

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, file);
	path[sizeof(path) - 1] = 0;

	if (stat(path, &st))
		panic("No such file %s! Type --help for further information\n",
		      path);
	if (st.st_uid != getuid())
		panic("You are not the owner of %s!\n", path);
}

static void check_config_exists_or_die(void)
{
	assert(home != NULL);
	check_file_or_die(home, FILE_CLIENTS);
	check_file_or_die(home, FILE_SERVERS);
	check_file_or_die(home, FILE_PRIVKEY);
	check_file_or_die(home, FILE_PUBKEY);
	check_file_or_die(home, FILE_USERNAM);
}

static void fetch_home_dir(void)
{
	home = getenv("HOME");
	if (!home)
		panic("No HOME defined!\n");
}

static int main_keygen(void)
{
	return 0;
}

static int main_client(char *dev)
{
	//Read from conf
	int udp = 0;
	char *host = "localhost";
	char *port = "6666";
	char *scope = "eth0";

	check_config_exists_or_die();
	return client_main(dev, host, port, scope, udp);
}

static int main_server(char *dev, char *port, int udp)
{
	check_config_exists_or_die();
	return server_main(dev, port, udp);
}

int main(int argc, char **argv)
{
	int c, opt_index, udp = 0;
	char *port = NULL;
	char *stun = NULL, *dev = NULL;
	enum working_mode wmode = MODE_UNKNOW;

	if (getuid() != geteuid())
		seteuid(getuid());
	if (getenv("LD_PRELOAD"))
		panic("curvetun cannot be preloaded!\n");

	fetch_home_dir();

	while ((c = getopt_long(argc, argv, short_options, long_options,
	       &opt_index)) != EOF) {
		switch (c) {
		case 'h':
			help();
			break;
		case 'v':
			version();
			break;
		case 'c':
			wmode = MODE_CLIENT;
			break;
		case 'd':
			dev = xstrdup(optarg);
			break;
		case 'k':
			wmode = MODE_KEYGEN;
			break;
		case 's':
			wmode = MODE_SERVER;
			break;
		case 'u':
			udp = 1;
			break;
		case 't':
			stun = xstrdup(optarg);
			break;
		case 'p':
			port = xstrdup(optarg);
			break;
		case '?':
			switch (optopt) {
			case 't':
			case 'd':
			case 'p':
				panic("Option -%c requires an argument!\n",
				      optopt);
			default:
				if (isprint(optopt))
					whine("Unknown option character "
					      "`0x%X\'!\n", optopt);
				die();
			}
		default:
			break;
		}
	}

	if (argc < 2)
		help();

	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	register_signal(SIGSEGV, muntrace_handler);

	header();

	switch (wmode) {
	case MODE_KEYGEN:
		main_keygen();
		break;
	case MODE_CLIENT:
		main_client(dev);
		break;
	case MODE_SERVER:
		if (!port)
			panic("No port specified!\n");
		if (stun) {
			print_stun_probe(stun, 3478, atoi(port));
			xfree(stun);
		}
		main_server(dev, port, udp);
		xfree(port);
		break;
	default:
		panic("Either select keygen, client or server mode!\n");
	}

	return 0;
}

