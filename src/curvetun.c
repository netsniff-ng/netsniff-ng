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
#include "write_or_die.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_scalarmult_curve25519.h"

enum working_mode {
	MODE_UNKNOW,
	MODE_KEYGEN,
	MODE_EXPORT,
	MODE_CLIENT,
	MODE_SERVER,
};

sig_atomic_t sigint = 0;

static const char *short_options = "kxcsvhp:t:d:u";

static struct option long_options[] = {
	{"client", optional_argument, 0, 'c'},
	{"dev", required_argument, 0, 'd'},
	{"port", required_argument, 0, 'p'},
	{"stun", required_argument, 0, 't'},
	{"keygen", no_argument, 0, 'k'},
	{"export", no_argument, 0, 'x'},
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
	printf("\ncurvetun %s, lightweight curve25519-based multiuser IP tunnel\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: curvetun [options]\n");
	printf("Options:\n");
	printf("  -k|--keygen             Generate public/private keypair\n");
	printf("  -x|--export             Export your public data for servers\n");
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
	printf("      3. To export your key for servers, use:\n");
	printf("           curvetun --export\n");
	printf("  B. Server:\n");
	printf("      1. curvetun --server --port 6666 --stun stunserver.org\n");
	printf("      2. ifconfig curves up\n");
	printf("      2. ifconfig curves 10.0.0.1/24\n");
	printf("      3. (setup route)\n");
	printf("  C. Client:\n");
	printf("      1. curvetun --client\n");
	printf("      2. ifconfig curvec up\n");
	printf("      2. ifconfig curvec 10.0.0.2/24\n");
	printf("      3. (setup route)\n");
	printf("  Where both participants have the following files specified:\n");
	printf("   ~/.curvetun/clients - Participants the server accepts\n");
	printf("        line-format:   username;pubkey\n");
	printf("   ~/.curvetun/servers - Possible servers the client can connect to\n");
	printf("        line-format:   alias;serverip|servername;port;udp|tcp;pubkey\n");
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
	printf("\ncurvetun %s, lightweight curve25519-based multiuser IP tunnel\n",
               VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	die();
}

static void check_file_or_die(char *home, char *file, int maybeempty)
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
	if (st.st_mode != (S_IRUSR | S_IWUSR | S_IFREG))
		panic("You have set too many permissions on %s (%o)!\n",
		      path, st.st_mode);
	if (maybeempty == 0 && st.st_size == 0)
		panic("%s is empty!\n", path);
}

static void check_config_exists_or_die(char *home)
{
	if (!home)
		panic("No home dir specified!\n");
	check_file_or_die(home, FILE_CLIENTS, 1);
	check_file_or_die(home, FILE_SERVERS, 1);
	check_file_or_die(home, FILE_PRIVKEY, 0);
	check_file_or_die(home, FILE_PUBKEY, 0);
	check_file_or_die(home, FILE_USERNAM, 0);
}

static char *fetch_home_dir(void)
{
	char *home = getenv("HOME");
	if (!home)
		panic("No HOME defined!\n");
	return home;
}

static void write_username(char *home)
{
	int fd, ret;
	char path[512], *eof;
	char user[512];

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_USERNAM);
	path[sizeof(path) - 1] = 0;

	printf("Username: [%s] ", getenv("USER"));
	fflush(stdout);

	memset(user, 0, sizeof(user));
	eof = fgets(user, sizeof(user), stdin);
	user[sizeof(user) - 1] = 0;
	user[strlen(user) - 1] = 0; /* omit last \n */

	if (strlen(user) == 0)
		strlcpy(user, getenv("USER"), sizeof(user));

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0)
		panic("Cannot open your username file!\n");
	ret = write(fd, user, strlen(user));
	if (ret != strlen(user))
		panic("Could not write username!\n");
	close(fd);

	info("Username written to %s!\n", path);
}

void create_curvedir(char *home)
{
	int ret, fd;
	char path[512];

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, ".curvetun/");
	path[sizeof(path) - 1] = 0;

	errno = 0;
	ret = mkdir(path, S_IRWXU);
	if (ret < 0 && errno != EEXIST)
		panic("Cannot create curvetun dir!\n");

	info("curvetun directory %s created!\n", path);

	/* We also create empty files for clients and servers! */
	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_CLIENTS);
	path[sizeof(path) - 1] = 0;

	fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0)
		panic("Cannot open clients file!\n");
	close(fd);

	info("Empty client file written to %s!\n", path);

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_SERVERS);
	path[sizeof(path) - 1] = 0;

	fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0)
		panic("Cannot open servers file!\n");
	close(fd);

	info("Empty server file written to %s!\n", path);
}

void create_keypair(char *home)
{
	int fd;
	ssize_t ret;
	unsigned char publickey[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES];
	unsigned char secretkey[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES];
	char path[512];

	info("Reading from /dev/random (this may take a while) ...\n");

	fd = open_or_die("/dev/random", O_RDONLY);
	ret = read_exact(fd, secretkey, sizeof(secretkey), 0);
	if (ret != sizeof(secretkey))
		panic("Cannot read from /dev/random!\n");
	close(fd);

	crypto_scalarmult_curve25519_base(publickey, secretkey);

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_PUBKEY);
	path[sizeof(path) - 1] = 0;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0)
		panic("Cannot open pubkey file!\n");
	ret = write(fd, publickey, sizeof(publickey));
	if (ret != sizeof(publickey))
		panic("Cannot write public key!\n");
	close(fd);

	info("Public key written to %s!\n", path);

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_PRIVKEY);
	path[sizeof(path) - 1] = 0;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0)
		panic("Cannot open privkey file!\n");
	ret = write(fd, secretkey, sizeof(secretkey));
	if (ret != sizeof(secretkey))
		panic("Cannot write private key!\n");
	close(fd);

	info("Private key written to %s!\n", path);
}

static int main_keygen(char *home)
{
	create_curvedir(home);
	write_username(home);
	create_keypair(home);
	return 0;
}

static int main_export(char *home)
{
	int fd, i;
	ssize_t ret;
	char path[512], tmp[64];

	check_config_exists_or_die(home);

	printf("Your exported public information:\n\n");

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_USERNAM);
	path[sizeof(path) - 1] = 0;

	fd = open_or_die(path, O_RDONLY);
	while ((ret = read(fd, tmp, sizeof(tmp))) > 0) {
		ret = write(1, tmp, ret);
	}
	close(fd);

	printf(";");

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_PUBKEY);
	path[sizeof(path) - 1] = 0;

	fd = open_or_die(path, O_RDONLY);
	ret = read(fd, tmp, sizeof(tmp));
	if (ret != crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES)
		panic("Cannot read public key!\n");
	for (i = 0; i < ret; ++i)
		if (i == ret - 1)
			printf("%02x\n\n", (unsigned char) tmp[i]);
		else
			printf("%02x:", (unsigned char) tmp[i]);
	close(fd);
	fflush(stdout);

	return 0;
}

static int main_client(char *home, char *dev, char *alias)
{
	//Read from conf
	int udp = 0;
	char *host = "localhost";
	char *port = "6666";
	char *scope = "eth0";

	check_config_exists_or_die(home);

	return client_main(dev, host, port, scope, udp);
}

static int main_server(char *home, char *dev, char *port, int udp)
{
	check_config_exists_or_die(home);

	return server_main(dev, port, udp);
}

int main(int argc, char **argv)
{
	int ret = 0, c, opt_index, udp = 0;
	char *port = NULL, *stun = NULL, *dev = NULL, *home = NULL;
	enum working_mode wmode = MODE_UNKNOW;

	if (getuid() != geteuid())
		seteuid(getuid());
	if (getenv("LD_PRELOAD"))
		panic("curvetun cannot be preloaded!\n");

	home = fetch_home_dir();

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
		case 'x':
			wmode = MODE_EXPORT;
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
			case 'u':
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
		ret = main_keygen(home);
		break;
	case MODE_EXPORT:
		ret = main_export(home);
		break;
	case MODE_CLIENT:
		ret = main_client(home, dev, NULL);
		break;
	case MODE_SERVER:
		if (!port)
			panic("No port specified!\n");
		if (stun)
			print_stun_probe(stun, 3478, strtoul(port, NULL, 10));
		ret = main_server(home, dev, port, udp);
		break;
	default:
		panic("Either select keygen, client or server mode!\n");
	}

	if (dev)
		xfree(dev);
	if (stun)
		xfree(stun);
	if (port)
		xfree(port);
	return ret;
}

