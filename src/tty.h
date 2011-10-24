/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef TTY_H
#define TTY_H

#include <termios.h>
#include <string.h>
#include <sys/ioctl.h>

#define DEFAULT_TTY_SIZE        80

#define __reset                 "0"
#define __bold                  "1"
#define __black                 "30"
#define __red                   "31"
#define __green                 "32"
#define __yellow                "33"
#define __blue                  "34"
#define __magenta               "35"
#define __cyan                  "36"
#define __white                 "37"
#define __on_black              "40"
#define __on_red                "41"
#define __on_green              "42"
#define __on_yellow             "43"
#define __on_blue               "44"
#define __on_magenta            "45"
#define __on_cyan               "46"
#define __on_white              "47"

#define colorize_start(fore)            "\033[" __##fore "m"
#define colorize_start_full(fore, back) "\033[" __##fore ";" __on_##back "m"
#define colorize_end()                  "\033[" __reset "m"

#define colorize_str(fore, text)                                     \
		colorize_start(fore) text colorize_end()
#define colorize_full_str(fore, back, text)                          \
		colorize_start_full(fore, back) text colorize_end()

static inline int get_tty_size(void)
{
#ifdef TIOCGSIZE
	struct ttysize ts = {0};
	int ret = ioctl(0, TIOCGSIZE, &ts);
	return (ret == 0 ? ts.ts_cols : DEFAULT_TTY_SIZE);
#elif defined(TIOCGWINSZ)
	struct winsize ts = {0};
	int ret = ioctl(0, TIOCGWINSZ, &ts);
	return (ret == 0 ? ts.ws_col : DEFAULT_TTY_SIZE);
#else
	return DEFAULT_TTY_SIZE;
#endif /* TIOCGSIZE */
}

static inline void set_tty_invisible(struct termios *orig)
{
	struct termios now;

	setvbuf(stdout, NULL, _IONBF ,0);

	tcgetattr(0, orig);
	memcpy(&now, orig, sizeof(*orig));
	now.c_lflag &= ~(ISIG | ICANON | ECHO);
	now.c_cc[VMIN] = 1;
	now.c_cc[VTIME] = 2;
	tcsetattr(0, TCSANOW, &now);
}

static inline void set_tty_visible(struct termios *orig)
{
	tcsetattr(0, TCSANOW, orig);
}

#endif /* TTY_H */
