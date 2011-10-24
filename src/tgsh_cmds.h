/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef TGSH_CMDS_H
#define TGSH_CMDS_H

#include <readline/readline.h>

#define MAX_MENU_ELEMS 100

extern int cmd_help(char *args);
extern int cmd_quit(char *args);
extern int cmd_stat(char *args);
extern int cmd_yack(char *args);

static inline int show_config(char *args) { return 0; }

struct shell_cmd {
	char *name;
	rl_icpfunc_t *callback;
	char *doc;
	struct shell_cmd *sub_cmd;
};

struct shell_cmd call_node[] = {
	{ "sip",  cmd_help, "Make a SIP call.",  NULL, },
	{ "yack", cmd_yack, "Make a yack call.", NULL, },
	{ NULL, NULL, NULL, NULL, },
};

struct shell_cmd show_node[] = {
	{ "stun", cmd_help,          "Show STUN probe result.", NULL, },
	{ "conf", show_config, "Show parsed config.",     NULL, },
	{ NULL, NULL, NULL, NULL, },
};

struct shell_cmd cmd_tree[] = {
	{ "help", cmd_help, "Show help.",          NULL, },
	{ "quit", cmd_quit, "Exit netyack shell.", NULL, },
	{ "ret",  cmd_stat, "Show return status.", NULL, },
	{ "call", NULL,     "Perform a call.",     call_node, },
	{ "take", cmd_stat, "Take a call.",        NULL, },
	{ "show", NULL,     "Show information.",   show_node, },
	{ NULL, NULL, NULL, NULL, },
};

#endif /* TGSH_CMDS_H */
