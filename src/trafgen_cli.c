#include <libcli.h>

#include "trafgen_conf.h"

int main_loop_interactive(struct mode *mode, char *confname)
{
	struct cli_def *cli;

	cli = cli_init();
	cli_set_banner(cli, "trafgen interactive mode");
	cli_set_hostname(cli, "txfnode");
//	cli_telnet_protocol(cli, 1);
	cli_done(cli);

	return 0;
}
