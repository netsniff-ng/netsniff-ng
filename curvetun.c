/*
 * curvetun - the cipherspace wormhole creator
 * Part of the netsniff-ng project
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Copyright 2011 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/fsuid.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>

#include "die.h"
#include "str.h"
#include "sig.h"
#include "stun.h"
#include "cookie.h"
#include "ioexact.h"
#include "xmalloc.h"
#include "curvetun.h"
#include "curve.h"
#include "config.h"
#include "curvetun_mgmt.h"
#include "ioops.h"
#include "tprintf.h"
#include "crypto.h"

enum working_mode {
	MODE_UNKNOW,
	MODE_KEYGEN,
	MODE_EXPORT,
	MODE_DUMPC,
	MODE_DUMPS,
	MODE_CLIENT,
	MODE_SERVER,
};

volatile sig_atomic_t sigint = 0;

static const char *short_options = "kxc::svhp:t:d:uCS46DN";
static const struct option long_options[] = {
	{"client",	optional_argument,	NULL, 'c'},
	{"dev",		required_argument,	NULL, 'd'},
	{"port",	required_argument,	NULL, 'p'},
	{"stun",	required_argument,	NULL, 't'},
	{"keygen",	no_argument,		NULL, 'k'},
	{"export",	no_argument,		NULL, 'x'},
	{"dumpc",	no_argument,		NULL, 'C'},
	{"dumps",	no_argument,		NULL, 'S'},
	{"no-logging",	no_argument,		NULL, 'N'},
	{"server",	no_argument,		NULL, 's'},
	{"udp",		no_argument,		NULL, 'u'},
	{"ipv4",	no_argument,		NULL, '4'},
	{"ipv6",	no_argument,		NULL, '6'},
	{"nofork",	no_argument,		NULL, 'D'},
	{"version",	no_argument,		NULL, 'v'},
	{"help",	no_argument,		NULL, 'h'},
	{NULL, 0, NULL, 0}
};

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
	case SIGTERM:
		sigint = 1;
		break;
	default:
		break;
	}
}

static void __noreturn help(void)
{
	printf("curvetun %s, lightweight curve25519-based IP tunnel\n", VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Usage: curvetun [options]\n"
	     "Options, general:\n"
	     "  -d|--dev <tun>          Networking tunnel device, e.g. tun0\n"
	     "  -p|--port <num>         Server port number (mandatory)\n"
	     "  -t|--stun <server>      Show public IP/Port mapping via STUN\n"
	     "  -c|--client[=alias]     Client mode, server alias optional\n"
	     "  -k|--keygen             Generate public/private keypair\n"
	     "  -x|--export             Export your public data for remote servers\n"
	     "  -C|--dumpc              Dump parsed clients\n"
	     "  -S|--dumps              Dump parsed servers\n"
	     "  -D|--nofork             Do not daemonize\n"
	     "  -s|--server             Server mode, options follow below\n"
	     "  -N|--no-logging         Disable server logging (for better anonymity)\n"
	     "  -u|--udp                Use UDP as carrier instead of TCP\n"
	     "  -4|--ipv4               Tunnel devices are IPv4\n"
	     "  -6|--ipv6               Tunnel devices are IPv6\n"
	     "  -v|--version            Print version and exit\n"
	     "  -h|--help               Print this help and exit\n\n"
	     "Example:\n"
	     "  See curvetun's man page for a configuration example.\n"
	     "  curvetun --server -4 -u -N --port 6666 --stun stunserver.org\n"
	     "  curvetun --client=ethz\n\n"
	     "  curvetun --keygen\n"
	     "  curvetun --export\n"
	     "Note:\n"
	     "  There is no default port specified, so that you are forced\n"
	     "  to select your own! For client/server status messages see syslog!\n"
	     "  This software is an experimental prototype intended for researchers.\n\n"
	     "Secret ingredient: 7647-14-5\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2011-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n"
	     "Swiss federal institute of technology (ETH Zurich)\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static void __noreturn version(void)
{
	printf("curvetun %s, Git id: %s\n", VERSION_LONG, GITVERSION);
	puts("lightweight curve25519-based IP tunnel\n"
	     "Note: Einstein-Rosen bridge not yet supported\n"
	     "http://www.netsniff-ng.org\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2011-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n"
	     "Swiss federal institute of technology (ETH Zurich)\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static void check_file_or_die(char *home, char *file, int maybeempty)
{
	char path[PATH_MAX];
	struct stat st;

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", home, file);

	if (stat(path, &st))
		panic("No such file %s! Type --help for further information\n",
		      path);

	if (!S_ISREG(st.st_mode))
		panic("%s is not a regular file!\n", path);

	if ((st.st_mode & ~S_IFREG) != (S_IRUSR | S_IWUSR))
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
	char path[PATH_MAX];
	char user[512];

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", home, FILE_USERNAM);

	printf("Username: [%s] ", getenv("USER"));
	fflush(stdout);

	memset(user, 0, sizeof(user));
	if (fgets(user, sizeof(user), stdin) == NULL)
		panic("Could not read from stdin!\n");
	user[sizeof(user) - 1] = 0;
	user[strlen(user) - 1] = 0; /* omit last \n */
	if (strlen(user) == 0)
		strlcpy(user, getenv("USER"), sizeof(user));

	fd = open_or_die_m(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

	ret = write(fd, user, strlen(user));
	if (ret != strlen(user))
		panic("Could not write username!\n");

	close(fd);

	printf("Username written to %s!\n", path);
}

static void create_curvedir(char *home)
{
	int ret;
	char path[PATH_MAX];

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", home, ".curvetun/");

	errno = 0;

	ret = mkdir(path, S_IRWXU);
	if (ret < 0 && errno != EEXIST)
		panic("Cannot create curvetun dir!\n");

	printf("curvetun directory %s created!\n", path);
	/* We also create empty files for clients and servers! */

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", home, FILE_CLIENTS);

	create_or_die(path, S_IRUSR | S_IWUSR);

	printf("Empty client file written to %s!\n", path);

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", home, FILE_SERVERS);

	create_or_die(path, S_IRUSR | S_IWUSR);

	printf("Empty server file written to %s!\n", path);
}

static void create_keypair(char *home)
{
	int fd, err = 0;
	ssize_t ret;
	unsigned char publickey[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES] = { 0 };
	unsigned char secretkey[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES] = { 0 };
	char path[PATH_MAX];
	const char * errstr = NULL;

	printf("Reading from %s (this may take a while) ...\n", HIG_ENTROPY_SOURCE);

	gen_key_bytes(secretkey, sizeof(secretkey));
	crypto_scalarmult_curve25519_base(publickey, secretkey);

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", home, FILE_PUBKEY);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		err = EIO;
		errstr = "Cannot open pubkey file!\n";
		goto out_noclose;
	}

	ret = write(fd, publickey, sizeof(publickey));
	if (ret != sizeof(publickey)) {
		err = EIO;
		errstr = "Cannot write public key!\n";
		goto out;
	}

	close(fd);

	printf("Public key written to %s!\n", path);

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", home, FILE_PRIVKEY);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		err = EIO;
		errstr = "Cannot open privkey file!\n";
		goto out_noclose;
	}

	ret = write(fd, secretkey, sizeof(secretkey));
	if (ret != sizeof(secretkey)) {
		err = EIO;
		errstr = "Cannot write private key!\n";
		goto out;
	}
out:
	close(fd);
out_noclose:
	xmemset(publickey, 0, sizeof(publickey));
	xmemset(secretkey, 0, sizeof(secretkey));

	if (err)
		panic("%s: %s", errstr, strerror(errno));
	else
		printf("Private key written to %s!\n", path);
}

static void check_config_keypair_or_die(char *home)
{
	int fd, err;
	ssize_t ret;
	const char * errstr = NULL;
	unsigned char publickey[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES];
	unsigned char publicres[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES];
	unsigned char secretkey[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES];
	char path[PATH_MAX];

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", home, FILE_PRIVKEY);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		err = EIO;
		errstr = "Cannot open privkey file!\n";
		goto out;
	}

	ret = read(fd, secretkey, sizeof(secretkey));
	if (ret != sizeof(secretkey)) {
		err = EIO;
		errstr = "Cannot read private key!\n";
		goto out;
	}

	close(fd);

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", home, FILE_PUBKEY);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		err = EIO;
		errstr = "Cannot open pubkey file!\n";
		goto out;
	}

	ret = read(fd, publickey, sizeof(publickey));
	if (ret != sizeof(publickey)) {
		err = EIO;
		errstr = "Cannot read public key!\n";
		goto out;
	}

	crypto_scalarmult_curve25519_base(publicres, secretkey);

	err = crypto_verify_32(publicres, publickey);
	if (err) {
		err = EINVAL;
		errstr = "WARNING: your keypair is corrupted!!! You need to "
			 "generate new keys!!!\n";
		goto out;
	}
out:
	close(fd);

	xmemset(publickey, 0, sizeof(publickey));
	xmemset(publicres, 0, sizeof(publicres));
	xmemset(secretkey, 0, sizeof(secretkey));

	if (err)
		panic("%s: %s\n", errstr, strerror(errno));
}

static int main_keygen(char *home)
{
	create_curvedir(home);
	write_username(home);
	create_keypair(home);
	check_config_keypair_or_die(home);

	return 0;
}

static int main_export(char *home)
{
	int fd, i;
	ssize_t ret;
	char path[PATH_MAX], tmp[64];

	check_config_exists_or_die(home);
	check_config_keypair_or_die(home);

	printf("Your exported public information:\n\n");

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", home, FILE_USERNAM);

	fd = open_or_die(path, O_RDONLY);

	while ((ret = read(fd, tmp, sizeof(tmp))) > 0) {
		ret = write(STDOUT_FILENO, tmp, ret);
	}

	close(fd);

	printf(";");

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", home, FILE_PUBKEY);

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

static int main_dumpc(char *home)
{
	check_config_exists_or_die(home);
	check_config_keypair_or_die(home);

	printf("Your clients:\n\n");

	parse_userfile_and_generate_user_store_or_die(home);

	dump_user_store();

	destroy_user_store();

	printf("\n");
	die();
	return 0;
}

static int main_dumps(char *home)
{
	check_config_exists_or_die(home);
	check_config_keypair_or_die(home);

	printf("Your servers:\n\n");

	parse_userfile_and_generate_serv_store_or_die(home);

	dump_serv_store();

	destroy_serv_store();

	printf("\n");
	die();
	return 0;
}

static void daemonize(const char *lockfile)
{
	char pidstr[8];
	mode_t lperm = S_IRWXU | S_IRGRP | S_IXGRP; /* 0750 */
	int lfp;

	if (getppid() == 1)
		return;

	if (daemon(0, 1))
		panic("Cannot daemonize: %s", strerror(errno));

	to_std_log(&stdout);
	to_std_log(&stderr);

	umask(lperm);
	if (lockfile) {
		lfp = open(lockfile, O_RDWR | O_CREAT | O_EXCL,
			   S_IRUSR | S_IWUSR | S_IRGRP);
		if (lfp < 0)
			syslog_panic("Cannot create lockfile at %s! "
				     "curvetun server already running?\n",
				     lockfile);

		slprintf(pidstr, sizeof(pidstr), "%u", getpid());
		if (write(lfp, pidstr, strlen(pidstr)) <= 0)
			syslog_panic("Could not write pid to pidfile %s",
				     lockfile);

		close(lfp);
	}
}

static int main_client(char *home, char *dev, char *alias, int daemon)
{
	int ret, udp;
	char *host, *port;

	check_config_exists_or_die(home);
	check_config_keypair_or_die(home);

	parse_userfile_and_generate_serv_store_or_die(home);

	get_serv_store_entry_by_alias(alias, alias ? strlen(alias) + 1 : 0,
				      &host, &port, &udp);
	if (!host || !port || udp < 0)
		panic("Did not find alias/entry in configuration!\n");

	printf("Using [%s] -> %s:%s via %s as endpoint!\n",
	       alias ? : "default", host, port, udp ? "udp" : "tcp");
	if (daemon)
		daemonize(NULL);

	ret = client_main(home, dev, host, port, udp);

	destroy_serv_store();

	return ret;
}

static int main_server(char *home, char *dev, char *port, int udp,
		       int ipv4, int daemon, int log)
{
	int ret;

	check_config_exists_or_die(home);
	check_config_keypair_or_die(home);

	if (daemon)
		daemonize(LOCKFILE);

	ret = server_main(home, dev, port, udp, ipv4, log);

	unlink(LOCKFILE);

	return ret;
}

int main(int argc, char **argv)
{
	int ret = 0, c, opt_index, udp = 0, ipv4 = -1, daemon = 1, log = 1;
	char *port = NULL, *stun = NULL, *dev = NULL, *home = NULL, *alias = NULL;
	enum working_mode wmode = MODE_UNKNOW;

	setfsuid(getuid());
	setfsgid(getgid());

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
		case 'D':
			daemon = 0;
			break;
		case 'N':
			log = 0;
			break;
		case 'C':
			wmode = MODE_DUMPC;
			break;
		case 'S':
			wmode = MODE_DUMPS;
			break;
		case 'c':
			wmode = MODE_CLIENT;
			if (optarg) {
				if (*optarg == '=')
					optarg++;
				alias = xstrdup(optarg);
			}
			break;
		case 'd':
			dev = xstrdup(optarg);
			break;
		case 'k':
			wmode = MODE_KEYGEN;
			break;
		case '4':
			ipv4 = 1;
			break;
		case '6':
			ipv4 = 0;
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
					printf("Unknown option character `0x%X\'!\n", optopt);
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
	register_signal(SIGTERM, signal_handler);
	register_signal(SIGPIPE, signal_handler);

	curve25519_selftest();

	switch (wmode) {
	case MODE_KEYGEN:
		ret = main_keygen(home);
		break;
	case MODE_EXPORT:
		ret = main_export(home);
		break;
	case MODE_DUMPC:
		ret = main_dumpc(home);
		break;
	case MODE_DUMPS:
		ret = main_dumps(home);
		break;
	case MODE_CLIENT:
		ret = main_client(home, dev, alias, daemon);
		break;
	case MODE_SERVER:
		if (!port)
			panic("No port specified!\n");
		if (stun)
			print_stun_probe(stun, 3478, strtoul(port, NULL, 10));
		ret = main_server(home, dev, port, udp, ipv4, daemon, log);
		break;
	default:
		die();
	}

	free(dev);
	free(stun);
	free(port);
	free(alias);

	return ret;
}
