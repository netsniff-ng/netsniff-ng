#include <libcli.h>

struct mode;

extern int main_loop_interactive(struct mode *mode, char *confname);

int main_loop_interactive(struct mode *mode, char *confname)
{
	struct cli_def *cli;

	cli = cli_init();
	cli_set_banner(cli, "libcli test environment");
	cli_set_hostname(cli, "router");
//	cli_telnet_protocol(cli, 1);

	cli_done(cli);
	return 0;
}
