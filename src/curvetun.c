/*
 * curvetun - the cipherspace wormhole creator
 * Part of the netsniff-ng project
 * Some code parts derived and modified from seccure:
 *   Copyright 2009 Bertram Poettering <seccure@point-at-infinity.org>
 *   Subject to the GPL.
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
#include <gcrypt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "xmalloc.h"
#include "netdev.h"
#include "version.h"
#include "stun.h"
#include "die.h"
#include "strlcpy.h"
#include "signals.h"
#include "tundev.h"
#include "curves.h"
#include "protocol.h"
#include "serialize.h"
#include "aes256ctr.h"

#define DEFAULT_CURVE   "secp521r1/nistp521"
#define DEFAULT_KEY_LEN 256
#define FILE_CLIENTS    ".curvetun/clients"
#define FILE_SERVERS    ".curvetun/servers"
#define FILE_PRIVKEY    ".curvetun/priv.key"
#define FILE_PUBKEY     ".curvetun/pub.key"
#define FILE_USERNAM    ".curvetun/username"

enum working_mode {
	MODE_UNKNOW,
	MODE_KEYGEN,
	MODE_CLIENT,
	MODE_SERVER,
};

enum client_mode {
	MODE_SINGLE,
	MODE_ALL_RROBIN,
	MODE_ALL_RANDOM,
	MODE_ALL_LATENCY,
};

static sig_atomic_t sigint = 0;

static char *home = NULL;

static const char *short_options = "kcm:svhp:t:";

static struct option long_options[] = {
	{"client", optional_argument, 0, 'c'},
	{"mode", required_argument, 0, 'm'},
	{"port", required_argument, 0, 'p'},
	{"stun", required_argument, 0, 't'},
	{"keygen", no_argument, 0, 'k'},
	{"server", no_argument, 0, 's'},
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
	printf("\ncurvetun %s, ``Elliptic Curve Crypto''-based IP-tunnel\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: curvetun [options]\n");
	printf("Options:\n");
	printf("  -k|--keygen             Generate public/private keypair\n");
	printf(" Client settings:\n");
	printf("  -c|--client[=alias]     Client mode, server alias optional\n");
	printf("  -m|--mode <mode>        Working mode, if no alias specified\n");
	printf("   `--- latency           Select server with lowest latency\n");
	printf("    `-- rrobin            Select servers in round robin\n");
	printf("     `- random            Select servers randomly (default)\n");
	printf(" Server settings:\n");
	printf("  -s|--server             Server mode\n");
	printf("  -p|--port <num>         Port number (mandatory)\n");
	printf("  -t|--stun <server>      Show public IP/Port mapping via STUN\n");
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
	printf("  B. Server: curvetun --server --port 6666 --stun stun.ekiga.net\n");
	printf("  C. Client: curvetun --client --mode random\n");
	printf("  Where both participants have the following files specified:\n");
	printf("   ~/.curvetun/clients - Participants the server accepts\n");
	printf("        line-format:   username:pubkey\n");
	printf("   ~/.curvetun/servers - Possible servers the client can connect to\n");
	printf("        line-format:   alias:serverip|servername:port:pubkey\n");
	printf("\n");
	printf("Note:\n");
	printf("  There is no default port specified, so that users are forced\n");
	printf("  to select their own!\n");
	printf("  Elliptic Curve Crypto powered by Bertram Poettering's SECCURE\n");
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
	printf("\ncurvetun %s, ``Elliptic Curve Crypto''-based IP-tunnel\n",
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
		panic("No such file  %s! Type --help for further information\n",
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

static void read_passphrase(char *hash)
{
	int fd, count = 0;
	char *md, ch;
	char path[512];
	ssize_t r;
	gcry_error_t ret;
	gcry_md_hd_t mh;

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_PRIVKEY);
	path[sizeof(path) - 1] = 0;

	ret = gcry_md_open(&mh, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
	if (gcry_err_code(ret))
		panic("Cannot initialize SHA256!\n");

	fd = open(path, O_RDONLY);
	if (fd < 0)
		panic("Cannot open your private keyfile!\n");
	while ((r = read(fd, &ch, 1)) > 0 && ch != '\n') {
		if (ch != '\r') {
			gcry_md_putc(mh, ch);
			count++;
		}
		if (r < 0)
			panic("Cannot read text line!\n");
	}
	close(fd);

	if (count < 64)
		panic("Error - Too few characters in priv.key!\n");

	gcry_md_final(mh);
	md = (char *) gcry_md_read(mh, 0);
	memcpy(hash, md, 32);
	gcry_md_close(mh);
}

static void write_privkey(void)
{
	int fd, fd2, count;
	char ch, path[512];
	ssize_t r;

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_PRIVKEY);
	path[sizeof(path) - 1] = 0;

	printf("Generating key from /dev/random!\n");
	printf("To fill entropy pool, move your mouse pointer "
	       "or press some keys for instance!\n");
	fflush(stdout);

	fd  = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	fd2 = open("/dev/random", O_RDONLY);
	if (fd < 0 || fd2 < 0)
		panic("Cannot open your private keyfile!\n");

	count = DEFAULT_KEY_LEN;
	while ((r = read(fd2, &ch, 1)) > 0 && count > 0) {
		if (r < 0)
			panic("Cannot read text line!\n");
		if (ch == '\n')
			continue;
		if (write(fd, &ch, 1) < 1)
			panic("Cannot write private key!\n");
		printf(".");
		fflush(stdout);
		count--;
	}

	if (write(fd, "\n", 1) < 1)
		panic("Cannot write private key!\n");
	close(fd2);
	close(fd);
	sync();

	printf("\n");
	printf("Private keyfile written to %s!\n", path);
}

static void write_pubkey(char *hash, size_t len)
{
	int fd, ret;
	char path[512];

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_PUBKEY);
	path[sizeof(path) - 1] = 0;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0)
		panic("Cannot open your private keyfile!\n");
	ret = write(fd, hash, len);
	if (ret != len)
		panic("Could not write pubkey!\n");
	close(fd);

	info("Public keyfile written to %s!\n", path);
}

static void write_username(void)
{
	int fd, ret;
	char path[512];
	char user[512];

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_USERNAM);
	path[sizeof(path) - 1] = 0;

	printf("Desired username: [%s] ", getenv("USER"));
	fflush(stdout);

	memset(user, 0, sizeof(user));
	fgets(user, sizeof(user), stdin);
	user[sizeof(user) - 1] = 0;
	user[strlen(user) - 1] = 0;

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

void create_curvedir(void)
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

	/* We also create empty files for clients and servers! */

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_CLIENTS);
	path[sizeof(path) - 1] = 0;

	fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0)
		panic("Cannot open clients file!\n");
	close(fd);

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_SERVERS);
	path[sizeof(path) - 1] = 0;

	fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0)
		panic("Cannot open servers file!\n");
	close(fd);
}

static int main_keygen(void)
{
	char *privkey, *pubkey;
	struct affine_point P;
	struct curve_params *cp;
	gcry_mpi_t d;

	info("Using curve %s!\n", DEFAULT_CURVE);

	cp = curve_by_name(DEFAULT_CURVE);
	pubkey = xzmalloc(cp->pk_len_compact + 1);
	privkey = gcry_malloc_secure(32);
	if (!privkey)
		panic("Out of secure memory!\n");

	create_curvedir();
	write_username();
	write_privkey();
	read_passphrase(privkey);

	d = hash_to_exponent(privkey, cp);
	gcry_free(privkey);
	P = pointmul(&cp->dp.base, d, &cp->dp);
	gcry_mpi_release(d);

	compress_to_string(pubkey, DF_COMPACT, &P, cp);
	write_pubkey(pubkey, cp->pk_len_compact);

	point_release(&P);
	curve_release(cp);

	return 0;
}

static int main_client(enum client_mode cmode)
{
	info("client\n");
	check_config_exists_or_die();
	return 0;
}

static int main_server(int port)
{
	info("server\n");
	check_config_exists_or_die();
	return 0;
}

int main(int argc, char **argv)
{
	int c, opt_index;
	uint16_t port;
	char *stun = NULL;
	enum working_mode wmode = MODE_UNKNOW;
	enum client_mode cmode = MODE_ALL_RANDOM;
	gcry_error_t ret;

	assert(gcry_check_version("1.4.1"));

	ret = gcry_control(GCRYCTL_INIT_SECMEM, 1);
	if (gcry_err_code(ret))
		panic("Cannot enable gcrypt's secure memory management!\n");

	ret = gcry_control(GCRYCTL_USE_SECURE_RNDPOOL, 1);
	if (gcry_err_code(ret))
		panic("Cannot enable gcrypt's secure random "
		      "number generator!\n");

	if (getuid() != geteuid())
		seteuid(getuid());
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
		case 'm':
			cmode = MODE_ALL_RANDOM;
			break;
		case 'k':
			wmode = MODE_KEYGEN;
			break;
		case 's':
			wmode = MODE_SERVER;
			break;
		case 't':
			stun = xstrdup(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case '?':
			switch (optopt) {
			case 'm':
			case 't':
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
		main_client(cmode);
		break;
	case MODE_SERVER:
		if (port == 0)
			panic("No port specified!\n");
		if (stun) {
			print_stun_probe(stun, 3478, port);
			xfree(stun);
		}
		main_server(port);
		break;
	default:
		panic("Either select keygen, client or server mode!\n");
	}

	gcry_control(GCRYCTL_TERM_SECMEM, 1);
	return 0;
}

